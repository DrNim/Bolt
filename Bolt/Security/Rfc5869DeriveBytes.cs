using System;
using System.Security.Cryptography;

namespace Bolt
{

    /// <summary>
    /// Implements HMAC-based key derivation functionality, HKDF, using the provided HMAC algorithm.
    /// </summary>
    internal sealed class Rfc5869DeriveBytes
    {

        #region " Properties "

        /// <summary>
        /// Gets the max length of bytes that can be derived by the operation.
        /// </summary>
        /// <value>The max length that can be derived by the operation.</value>
        public int MaxLength
        {
            get { return _maxLength; }
        }

        #endregion

        #region " Members "

        private HMAC _hmac;

        private int _maxLength;
        private int _hashLength;

        #endregion

        #region " Constructor "

        /// <summary>
        /// Initializes a new instance of the <see cref="Rfc5869DeriveBytes"/> class using a hash algorithim, a key, and salt to derive the internal key.
        /// </summary>
        /// <param name="hashAlgorithm">The HMAC hash implementation to use.</param>
        /// <param name="key">The key used to derive the internal key.</param>
        /// <param name="salt">The salt used to derive the internal key.</param>
        /// <exception cref="ArgumentNullException">The hashAlgorithim or key is null.</exception>
        public Rfc5869DeriveBytes(HMACAlgorithmName hashAlgorithm, byte[] key, byte[] salt = null)
        {
            if (hashAlgorithm.Name == null)
            {
                throw new ArgumentNullException(nameof(hashAlgorithm));
            }

            Initialize(HMAC.Create(hashAlgorithm.Name), key, salt);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Rfc5869DeriveBytes"/> class using an HMAC, a key, and salt to derive the internal key.
        /// </summary>
        /// <param name="hmac">The HMAC implementation to use.</param>
        /// <param name="key">The key used to derive the internal key.</param>
        /// <param name="salt">The salt used to derive the internal key.</param>
        /// <exception cref="ArgumentNullException">The hmac or key is null.</exception>
        public Rfc5869DeriveBytes(HMAC hmac, byte[] key, byte[] salt = null)
        {
            if (hmac == null)
            {
                throw new ArgumentNullException(nameof(hmac));
            }

            Initialize(hmac, key, salt);
        }

        private void Initialize(HMAC hmac, byte[] key, byte[] salt)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            _hmac = hmac;
            _hmac.Key = salt ?? new byte[_hmac.HashSize / 8];
            _hmac.Key = _hmac.ComputeHash(key);

            _hashLength = _hmac.HashSize / 8;
            _maxLength = _hashLength * 255;
        }

        #endregion

        #region " Derivation "

        /// <summary>
        /// Returns the pseudo-random key for this object.
        /// </summary>
        /// <param name="cb">The number of pseudo-random key bytes to generate.</param>
        /// <param name="info">Optional context and application specific information.</param>
        /// <returns>A byte array filled with pseudo-random key bytes.</returns>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="cb"/> is out of range. This parameter requires a non-negative number less than <see cref="MaxLength"/>.</exception>
        public byte[] GetBytes(int cb, byte[] info = null)
        {
            if (cb < 0 || cb > _maxLength)
            {
                throw new ArgumentOutOfRangeException(nameof(cb));
            }

            if (info == null)
            {
                info = new byte[0];
            }

            byte[] hash = new byte[0];
            byte[] output = new byte[cb];
            byte[] buffer = new byte[info.Length + 1];

            int bytesToCopy = 0;
            int bytesCopied = 0;
            int bufferSize = _hashLength + info.Length + 1;

            byte counter = 1;

            while (bytesCopied < cb)
            {
                Buffer.BlockCopy(hash, 0, buffer, 0, hash.Length);
                Buffer.BlockCopy(info, 0, buffer, hash.Length, info.Length);
                buffer[buffer.Length - 1] = counter++;

                hash = _hmac.ComputeHash(buffer);

                if (buffer.Length < bufferSize)
                {
                    buffer = new byte[bufferSize];
                }

                bytesToCopy = Math.Min(hash.Length, cb - bytesCopied);
                Buffer.BlockCopy(hash, 0, output, bytesCopied, bytesToCopy);
                bytesCopied += bytesToCopy;
            }

            return output;
        }

        #endregion

    }

}
