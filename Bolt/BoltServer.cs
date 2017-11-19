using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Bolt
{

    public sealed class BoltServer : BoltBase
    {

        #region " Properties "
 
        public byte ChallengeDifficulty
        {
            get
            {
                return _challengeDifficulty;
            }
            set
            {
                if (value > this.MaxChallengeDifficulty)
                {
                    throw new ArgumentOutOfRangeException(nameof(value));
                }

                _challengeDifficulty = value;
            }
        }

        public byte MaxChallengeDifficulty
        {
            get { return HashPuzzle.MaxDifficulty; }
        }

        #endregion

        #region " Events "

        public event EventHandler ChallengeFailed;

        #endregion

        #region " Event Handlers " 

        private void OnChallengeFailed()
        {
            EventHandler handler = ChallengeFailed;

            handler?.Invoke(this, EventArgs.Empty);
        }

        #endregion

        #region " Members "

        private bool _validateEcho;
        private byte _challengeDifficulty;
 
        private Tag _remoteTag;

        #endregion

        #region " Constructor "

        public BoltServer()
        {
            _challengeDifficulty = 20;
        }

        #endregion

        public override void Initialize()
        {
            if (LocalTag == null)
            {
                throw new NullReferenceException(string.Format("{0} is null.", nameof(LocalTag)));
            }

            if(MutualAuthenticationRequired && TrustedIssuers == null)
            {
                throw new NullReferenceException(string.Format("{0} is null.", nameof(TrustedIssuers)));
            }
  
            BufferFrame(new ServerNegotiateFrame(), FrameState.ServerNegotiate);
        }

        internal override void OnFrameProcessed(BaseFrame frame)
        {
            switch (State)
            {
                case FrameState.ServerNegotiate:
                    HandleNegotiateFrame((ServerNegotiateFrame)frame);
                    break;
                case FrameState.ServerExchange:
                    HandleExchangeFrame((ServerExchangeFrame)frame);
                    break;
                case FrameState.ServerValidate:
                    HandleValidateFrame((ServerValidateFrame)frame);
                    break;
                case FrameState.ServerEcho:
                    HandleEchoFrame((ServerEchoFrame)frame);
                    break;
            }
        }

        private void HandleNegotiateFrame(ServerNegotiateFrame frame)
        {
            if (frame.MinVersion > MAX_VERSION || frame.MaxVersion < MIN_VERSION)
            {
                OnExceptionThrown(new InvalidDataException("Invalid protocol version."));
                return;
            }

            Version = Math.Min(frame.MaxVersion, MAX_VERSION);
            ServerNonce = CreateNonce(NONCE_LENGTH);

            BufferFrame(new ServerExchangeFrame(), FrameState.ServerExchange);
            SendNegotiateFrame();
        }

        private void HandleExchangeFrame(ServerExchangeFrame frame)
        {
            if (frame.Success)
            {
                if (frame.Tag.Length > MAX_TAG_LENGTH)
                {
                    OnExceptionThrown(new InvalidDataException("Invalid tag length."));
                    return;
                }

                HashPuzzle puzzle = new HashPuzzle(HashAlgorithmName.SHA256, ChallengeDifficulty, ServerNonce);

                if (!puzzle.VerifySolution(frame.Solution))
                {
                    OnExceptionThrown(new InvalidDataException("Challenge failed."));
                    return;
                }

                if (frame.Tag.Length == 0)
                {
                    if (MutualAuthenticationRequired)
                    {
                        OnExceptionThrown(new InvalidDataException("Tag missing."));
                        return;
                    }
                }
                else
                { 
                    _remoteTag = Tag.Deserialize(frame.Tag);

                    if (TrustedIssuers != null && _remoteTag.Verify(TrustedIssuers))
                    {
                        IsMutuallyAuthenticated = true;
                    }
                    if (MutualAuthenticationRequired)
                    {
                        OnExceptionThrown(new InvalidDataException("Invalid tag."));
                        return;
                    } 
                }

                ClientNonce = frame.Nonce;

                BufferFrame(new ServerValidateFrame(), FrameState.ServerValidate);
                SendExchangeFrame(GetPublicKey(), IsMutuallyAuthenticated);
            }
            else
            {
                OnChallengeFailed();

                //TODO: check if we're disposed

                ServerNonce = CreateNonce(NONCE_LENGTH);

                BufferFrame(new ServerExchangeFrame(), FrameState.ServerExchange);
                SendNegotiateFrame();
            }
        }

        private void HandleValidateFrame(ServerValidateFrame frame)
        {
            if (IsMutuallyAuthenticated)
            {
                List<byte[]> signatureParts = new List<byte[]>();
                signatureParts.Add(frame.PublicKey);
                signatureParts.Add(ServerNonce);
                signatureParts.Add(LocalTag.RawData);

                if (!VerifyData(_remoteTag.Holder.Key, frame.Signature, signatureParts.ToArray()))
                {
                    OnExceptionThrown(new InvalidDataException("Invalid signature."));
                    return;
                }
            }

            InitializeCrypto(frame.PublicKey, true);
            BufferFrame(new ServerEchoFrame(), FrameState.ServerEcho);
        }

        private void HandleEchoFrame(ServerEchoFrame frame)
        {
            if (_validateEcho)
            {
                if (!CompareBytes(frame.Nonce, 0, ServerNonce, 0, ServerNonce.Length))
                {
                    OnExceptionThrown(new InvalidDataException("Nonce echo failed."));
                    return;
                }

                Establish();
            }
            else
            {
                _validateEcho = true;

                ClientNonce = frame.Nonce;
                ServerNonce = CreateNonce(NONCE_LENGTH);

                BufferFrame(new ServerEchoFrame(), FrameState.ServerEcho);
                SendEchoFrame();
            }
        }

        private void SendNegotiateFrame()
        {
            ClientNegotiateFrame frame = new ClientNegotiateFrame();
            frame.MinVersion = MIN_VERSION;
            frame.MaxVersion = MAX_VERSION;
            frame.Nonce = ServerNonce;
            frame.IsMutual = MutualAuthenticationRequired;
            frame.Difficulty = ChallengeDifficulty;

            SendFrame(frame);
        }

        private void SendExchangeFrame(byte[] publicKey, bool isMutual)
        {
            List<byte[]> signatureParts = new List<byte[]>();
            signatureParts.Add(publicKey);
            signatureParts.Add(ClientNonce);
            signatureParts.Add( new byte[] { isMutual ? (byte)1 : (byte)0 });

            if (IsMutuallyAuthenticated)
            {
                signatureParts.Add(_remoteTag.RawData);
            }

            ClientExchangeFrame frame = new ClientExchangeFrame();
            frame.IsMutual = isMutual;
            frame.PublicKey = publicKey;
            frame.Signature = SignData(LocalTag.Holder.Key, signatureParts.ToArray());
            frame.Tag = LocalTag.RawData;

            SendFrame(frame);
        }

        private void SendEchoFrame()
        {
            ClientEchoFrame frame = new ClientEchoFrame();
            frame.ClientNonce = ClientNonce;
            frame.ServerNonce = ServerNonce;

            SendFrame(frame);
        }
    }

}