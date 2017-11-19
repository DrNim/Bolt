using System;
using System.IO;
using System.Security.Cryptography;

namespace Bolt
{
    //server sends certificate (signed by a trusted issuer, containing their and the issuers public key), signed with the holders private key
    //client finds the trusted issuer in it's trust list and verifies the certificate, then verifies the holder signature
    //client sends a random nonce to the server to be signed, if it's sent back and verifies this proves the server has the private key and it's safe to continue

    //Signatures should be truncated to 96bits and be calculating using a counter to detect missing / duplicated packets
    //Server must sign a randomly generated nonce from the client to prove it's access to the private key, otherwise someone could simply retransmit a captured certificate

    //Mutual authentication requires the client to send a signature of the server certificate, so that an injected cert will be detected by the server upon receiving it.

    //Update keys every N bytes

    public abstract class BoltBase
    {

        #region " Consts "

        internal const byte MIN_VERSION = 1;
        internal const byte MAX_VERSION = 1;
        internal const byte NONCE_LENGTH = 16;
        internal const byte SOLUTION_LENGTH = 4;
        internal const byte MAX_DIFFICULTY = 24;
        internal const ushort MAX_TAG_LENGTH = 1024;

        internal const byte AES_IV_SIZE = 16;
        internal const byte AES_KEY_SIZE = 16;
        internal const byte MAC_KEY_SIZE = 64;

        internal const byte HMAC_SIZE = 16;
        internal const byte PREFIX_SIZE = HMAC_SIZE + 2;
        internal const uint BUFFER_SIZE = ushort.MaxValue + PREFIX_SIZE;

        #endregion

        internal enum FrameState
        {
            ClientEcho,
            ClientExchange,
            ClientNegotiate,
            ServerEcho,
            ServerExchange,
            ServerNegotiate,
            ServerValidate,
            Established
        }

        #region " Properties "

        public Tag LocalTag
        {
            get { return _localTag; }
            set { _localTag = value; }
        }

        public EntityCollection TrustedIssuers
        {
            get { return _trustedIssuers; }
            set { _trustedIssuers = value; }
        }

        public bool MutualAuthenticationRequired
        {
            get { return _mutualAuthenticationRequired; }
            set { _mutualAuthenticationRequired = value; }
        }

        public bool IsMutuallyAuthenticated
        {
            get { return _isMutuallyAuthenticated; }
            internal set { _isMutuallyAuthenticated = value; }
        }

        internal FrameState State
        {
            get { return _state; }
        }

        public byte Version
        {
            get { return _version; }
            internal set { _version = value; }
        }

        internal byte[] ClientNonce
        {
            get { return _clientNonce; }
            set { _clientNonce = value; }
        }

        internal byte[] ServerNonce
        {
            get { return _serverNonce; }
            set { _serverNonce = value; }
        }

        //internal byte[] PublicKey
        //{
        //    get { return _publicKey; }
        //}

        #endregion

        #region " Events "

        public event EventHandler Established;
        public event EventHandler<DataEncodedEventArgs> DataEncoded;
        public event EventHandler<DataDecodedEventArgs> DataDecoded;
        public event EventHandler<ExceptionThrownEventArgs> ExceptionThrown;

        #endregion

        #region " Event Handlers "

        protected void OnExceptionThrown(Exception ex)
        {
            //TODO: Dispose the instance?

            EventHandler<ExceptionThrownEventArgs> handler = ExceptionThrown;

            handler?.Invoke(this, new ExceptionThrownEventArgs(ex));
        }

        private void OnEstablished()
        {
            EventHandler handler = Established;

            handler?.Invoke(this, EventArgs.Empty);
        }

        private void OnDataEncoded(byte[] buffer, int offset, int count, byte[] header)
        {
            EventHandler<DataEncodedEventArgs> handler = DataEncoded;

            handler?.Invoke(this, new DataEncodedEventArgs(buffer, offset, count, header));
        }

        private void OnDataDecoded(byte[] buffer, int offset, int count)
        {
            EventHandler<DataDecodedEventArgs> handler = DataDecoded;

            handler?.Invoke(this, new DataDecodedEventArgs(buffer, offset, count));
        }

        #endregion

        #region " Members "

        private byte _version;

        private Tag _localTag;
        private EntityCollection _trustedIssuers;
        private bool _mutualAuthenticationRequired;

        private BaseFrame _frame;
        private FrameState _state;

        private bool _secure;
        private bool _isMutuallyAuthenticated;

        private HMACSHA256 _signer;
        private HMACSHA256 _verifier;

        private ICryptoTransform _encryptor;
        private ICryptoTransform _decryptor;

        private byte[] _buffer;
        private int _offset; //TODO: Not used, maybe it's not a good idea to allow user-supplied buffers since they could corrupt encrypted data / signaturess

        private int _inCounter;
        private int _outCounter;

        private int _bytesToBuffer;
        private int _bufferPosition;

        private bool _disposed;

        private byte[] _clientNonce;
        private byte[] _serverNonce;

        private ECDiffieHellman _ecdh;

        #endregion

        #region " Constructor "

        public BoltBase()
        {
            _buffer = new byte[BUFFER_SIZE];
        }

        #endregion

        protected byte[] GetPublicKey()
        {
            _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521);

            return _ecdh.PublicKey.ToByteArray();
        }

        protected void InitializeCrypto(byte[] remoteKey, bool isAuthority)
        {
            ECDiffieHellmanPublicKey publicKey = ECDiffieHellmanCngPublicKey.FromByteArray(remoteKey, CngKeyBlobFormat.EccPublicBlob);
            byte[] keyMaterial = _ecdh.DeriveKeyMaterial(publicKey);

            byte[] salt = new byte[_clientNonce.Length + _serverNonce.Length];
            Buffer.BlockCopy(_serverNonce, 0, salt, 0, _serverNonce.Length);
            Buffer.BlockCopy(_clientNonce, 0, salt, _serverNonce.Length, _clientNonce.Length);

            Rfc5869DeriveBytes kdf = new Rfc5869DeriveBytes(HMACAlgorithmName.HMACSHA256, keyMaterial, salt);
            byte[] cryptoBlock = kdf.GetBytes((AES_IV_SIZE + AES_KEY_SIZE + MAC_KEY_SIZE) * 2);

            byte[] serverAesIv = new byte[AES_IV_SIZE];
            byte[] serverAesKey = new byte[AES_KEY_SIZE];
            byte[] serverMacKey = new byte[MAC_KEY_SIZE];
            byte[] clientAesIv = new byte[AES_IV_SIZE];
            byte[] clientAesKey = new byte[AES_KEY_SIZE];
            byte[] clientMacKey = new byte[MAC_KEY_SIZE];

            int offset = 0;

            offset += BlockCopy(cryptoBlock, offset, serverAesIv, 0, serverAesIv.Length);
            offset += BlockCopy(cryptoBlock, offset, serverAesKey, 0, serverAesKey.Length);
            offset += BlockCopy(cryptoBlock, offset, serverMacKey, 0, serverMacKey.Length);
            offset += BlockCopy(cryptoBlock, offset, clientAesIv, 0, clientAesIv.Length);
            offset += BlockCopy(cryptoBlock, offset, clientAesKey, 0, clientAesKey.Length);
            offset += BlockCopy(cryptoBlock, offset, clientMacKey, 0, clientMacKey.Length);

            _signer = new HMACSHA256();
            _signer.Key = isAuthority ? serverMacKey : clientMacKey;

            _verifier = new HMACSHA256();
            _verifier.Key = isAuthority ? clientMacKey : serverMacKey;

            AesCounterModeProvider provider1 = new AesCounterModeProvider();
            provider1.IV = isAuthority ? serverAesIv : clientAesIv;
            provider1.Key = isAuthority ? serverAesKey : clientAesKey;

            AesCounterModeProvider provider2 = new AesCounterModeProvider();
            provider2.IV = isAuthority ? clientAesIv : serverAesIv;
            provider2.Key = isAuthority ? clientAesKey : serverAesKey;

            _encryptor = provider1.CreateEncryptor();
            _decryptor = provider2.CreateDecryptor();

            _secure = true;
        }

        protected static int BlockCopy(byte[] src, int srcOffset, byte[] dst, int dstOffset, int count)
        {
            Buffer.BlockCopy(src, srcOffset, dst, dstOffset, count);

            return count;
        }

        public abstract void Initialize();

        public void Encode(byte[] buffer, int offset, ushort count)
        {
            if (_state != FrameState.Established)
            {
                throw new InvalidOperationException("Session has not been established.");
            }

            EncodeInternal(buffer, offset, count);
        }

        protected void EncodeInternal(byte[] buffer, int offset, ushort count)
        {
            byte[] header = new byte[PREFIX_SIZE];
            byte[] size = BitConverter.GetBytes(count);
            byte[] counter = BitConverter.GetBytes(_outCounter++);

            _encryptor.TransformBlock(size, 0, size.Length, header, HMAC_SIZE);
            _encryptor.TransformBlock(buffer, offset, count, buffer, offset);

            _signer.TransformBlock(counter, 0, counter.Length, null, 0);
            _signer.TransformBlock(header, HMAC_SIZE, size.Length, null, 0);
            _signer.TransformFinalBlock(buffer, offset, count);

            Buffer.BlockCopy(_signer.Hash, 0, header, 0, HMAC_SIZE);
            _signer.Initialize();

            OnDataEncoded(buffer, offset, count, header);
        }

        public void Decode(byte[] buffer, int offset, int count)
        {
            int bytesCopied = 0;
            int bytesToCopy = 0;

            while (!_disposed)
            {
                bytesToCopy = Math.Min(_bytesToBuffer - _bufferPosition, count - bytesCopied);

                if (bytesToCopy == 0)
                {
                    break;
                }

                Buffer.BlockCopy(buffer, offset + bytesCopied, _buffer, _offset + _bufferPosition, bytesToCopy);
                bytesCopied += bytesToCopy;
                _bufferPosition += bytesToCopy;

                if (_bufferPosition == _bytesToBuffer)
                {
                    OnBufferReady(_buffer);
                }
            }
        }

        private void OnBufferReady(byte[] buffer)
        {
            if (!_secure)
            {
                ProcessFrame(buffer, _offset, _bytesToBuffer);
                return;
            }

            if (_bytesToBuffer == PREFIX_SIZE)
            {
                byte[] size = new byte[2];

                _decryptor.TransformBlock(_buffer, _offset + HMAC_SIZE, 2, size, 0);
                _bytesToBuffer += BitConverter.ToUInt16(size, 0);
            }
            else
            {
                byte[] counter = BitConverter.GetBytes(_inCounter++);

                _verifier.TransformBlock(counter, 0, counter.Length, null, 0);
                _verifier.TransformFinalBlock(_buffer, _offset + HMAC_SIZE, _bytesToBuffer - HMAC_SIZE);

                if (!CompareBytes(_verifier.Hash, 0, _buffer, _offset, HMAC_SIZE))
                {
                    OnExceptionThrown(new InvalidDataException("Invalid record signature."));
                    return;
                }

                _verifier.Initialize();
                _decryptor.TransformBlock(_buffer, _offset + PREFIX_SIZE, _bytesToBuffer - PREFIX_SIZE, _buffer, _offset + PREFIX_SIZE);

                if (_state == FrameState.Established)
                {
                    OnDataDecoded(buffer, _offset + PREFIX_SIZE, _bytesToBuffer - PREFIX_SIZE);

                    _bufferPosition = 0;
                    _bytesToBuffer = PREFIX_SIZE;
                }
                else
                {
                    ProcessFrame(buffer, _offset + PREFIX_SIZE, _bytesToBuffer - PREFIX_SIZE);
                }
            }
        }

        private void ProcessFrame(byte[] buffer, int offset, int count)
        {
            int pendingBytes = 0;

            while (pendingBytes == 0)
            {
                pendingBytes = _frame.Deserialize(buffer, offset, count);
            }

            if (pendingBytes == -1)
            {
                OnFrameProcessed(_frame);
            }
            else
            {
                _bytesToBuffer += pendingBytes;
            }
        }

        internal void SendFrame(BaseFrame frame)
        {
            byte[] data = frame.Serialize();

            if (_secure)
            {
                EncodeInternal(data, 0, (ushort)data.Length);
            }
            else
            {
                OnDataEncoded(data, 0, data.Length, new byte[0]);
            }
        }

        internal void BufferFrame(BaseFrame frame, FrameState state)
        {
            _frame = frame;
            _state = state;
            _bufferPosition = 0;

            if (_secure)
            {
                _bytesToBuffer = PREFIX_SIZE;
            }
            else
            {
                _bytesToBuffer = frame.InitialSize;
            }

        }

        internal abstract void OnFrameProcessed(BaseFrame frame);

        protected static bool CompareBytes(byte[] src1Buffer, int src1Offset, byte[] src2Buffer, int src2Offset, int count)
        {
            for (int i = 0; i < count; i++)
            {
                if (src1Buffer[src1Offset + i] != src2Buffer[src2Offset + i])
                {
                    return false;
                }
            }

            return true;
        }

        internal void Establish()
        {
            //TODO: Clean up state objects

            _bufferPosition = 0;
            _bytesToBuffer = PREFIX_SIZE;

            _state = FrameState.Established;

            OnEstablished();
        }

        protected static byte[] CreateNonce(int length)
        {
            byte[] buffer = new byte[length];

            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(buffer, 0, buffer.Length);

            return buffer;
        }

        protected static bool VerifyData(ECDsa key, byte[] signature, params byte[][] data)
        {
            byte[] hash = HashData(HashAlgorithmName.SHA256, data);
            return key.VerifyHash(hash, signature);
        }

        protected static byte[] SignData(ECDsa key, params byte[][] data)
        {
            byte[] hash = HashData(HashAlgorithmName.SHA256, data);
            return key.SignHash(hash);
        }

        private static byte[] HashData(HashAlgorithmName hashAlgorithm, params byte[][] data)
        {
            byte[] buffer = null;
            HashAlgorithm algorithm = HashAlgorithm.Create(hashAlgorithm.Name);

            for (int i = 0; i < data.Length - 1; i++)
            {
                buffer = data[i];
                algorithm.TransformBlock(buffer, 0, buffer.Length, null, 0);
            }

            buffer = data[data.Length - 1];
            algorithm.TransformFinalBlock(buffer, 0, buffer.Length);

            return algorithm.Hash;
        }



    }

}