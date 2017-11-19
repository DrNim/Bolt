using System;
using System.Security.Cryptography;

namespace Bolt
{

    //NOTE: Not reccomended if BlockSize is less than 64.
    internal abstract class CounterModeProviderBase : SymmetricAlgorithm
    {

        protected abstract SymmetricAlgorithm CreateCryptoProvider();

        #region " Properties "

        public sealed override CipherMode Mode
        {
            get { return _cryptoProvider.Mode; }
        }

        public sealed override PaddingMode Padding
        {
            get { return _cryptoProvider.Padding; }
        }

        public sealed override int FeedbackSize
        {
            get { return _cryptoProvider.FeedbackSize; }
        }

        public sealed override byte[] IV
        {
            get { return _iv; }
            set { _iv = value; }
        }

        public sealed override byte[] Key
        {
            get { return _cryptoProvider.Key; }
            set { _cryptoProvider.Key = value; }
        }

        public sealed override int KeySize
        {
            get { return _cryptoProvider.KeySize; }
            set { _cryptoProvider.KeySize = value; }
        }

        public sealed override KeySizes[] LegalBlockSizes
        {
            get { return _cryptoProvider.LegalBlockSizes; }
        }

        public sealed override KeySizes[] LegalKeySizes
        {
            get { return _cryptoProvider.LegalKeySizes; }
        }

        public sealed override int BlockSize
        {
            get { return _cryptoProvider.BlockSize; }
            set { _cryptoProvider.BlockSize = value; }
        }

        public uint Counter
        {
            get { return _counter; }
            set { _counter = value; }
        }

        #endregion

        #region " Members "

        private byte[] _iv;
        private uint _counter;

        private SymmetricAlgorithm _cryptoProvider;

        #endregion

        #region " Constructor "

        public CounterModeProviderBase()
        {
            _counter = 1;
            _cryptoProvider = OnCreateCryptoProvider();
        }

        #endregion

        #region " ICryptoTransform "

        public sealed override ICryptoTransform CreateEncryptor()
        {
            return CreateEncryptor(_cryptoProvider.Key, _iv, _counter);
        }

        public sealed override ICryptoTransform CreateDecryptor()
        {
            return CreateDecryptor(_cryptoProvider.Key, _iv, _counter);
        }

        public sealed override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return CreateEncryptor(rgbKey, rgbIV, _counter);
        }

        public sealed override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return CreateDecryptor(rgbKey, rgbIV, _counter);
        }

        public ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV, uint counter)
        {
            return CreateCryptoTransform(rgbKey, rgbIV, counter);
        }

        public ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV, uint counter)
        {
            return CreateCryptoTransform(rgbKey, rgbIV, counter);
        }

        private ICryptoTransform CreateCryptoTransform(byte[] rgbKey, byte[] rgbIV, uint counter)
        {
            if (_cryptoProvider.BlockSize < 32)
            {
                throw new ArgumentOutOfRangeException(nameof(_cryptoProvider.BlockSize));
            }

            if (rgbIV == null)
            {
                rgbIV = GetRandomBytes((_cryptoProvider.BlockSize - 32) / 8);
            }

            ICryptoTransform transform = _cryptoProvider.CreateEncryptor(rgbKey, _cryptoProvider.IV);

            return new CounterModeCryptoTransform(transform, _cryptoProvider.BlockSize, rgbIV, counter);
        }

        #endregion

        #region " Key / IV "

        public sealed override void GenerateIV()
        {
            if (_cryptoProvider.BlockSize < 32)
            {
                throw new ArgumentOutOfRangeException(nameof(_cryptoProvider.BlockSize));
            }

            _iv = GetRandomBytes((_cryptoProvider.BlockSize - 32) / 8);
        }

        public sealed override void GenerateKey()
        {
            _cryptoProvider.Key = GetRandomBytes(_cryptoProvider.KeySize / 8);
        }

        #endregion

        #region " Events "

        private SymmetricAlgorithm OnCreateCryptoProvider()
        {
            SymmetricAlgorithm cryptoProvider = CreateCryptoProvider();

            cryptoProvider.Padding = PaddingMode.None;
            cryptoProvider.Mode = CipherMode.ECB;

            return cryptoProvider;
        }

        #endregion

        #region " Helpers "

        public static uint GetCounterAtOffset(long offset, int blockSize)
        {
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }

            if (blockSize < 32)
            {
                throw new ArgumentOutOfRangeException(nameof(blockSize));
            }

            return (uint)(offset / (blockSize / 8));
        }

        private static byte[] GetRandomBytes(int count)
        {
            byte[] output = new byte[count];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

            rng.GetBytes(output);

            return output;
        }

        #endregion

        #region " IDispose "

        protected override void Dispose(bool disposing)
        {
            _cryptoProvider.Dispose();
        }

        #endregion

    }

}
