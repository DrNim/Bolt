using System;
using System.Security.Cryptography;

namespace Bolt
{

    /// <summary>
    /// Computes and verifies proof-of-work challenges inspired by Hashcash to deter denial of service attacks and other service abuses such as spam.
    /// </summary>
    internal sealed class HashPuzzle
    {

        #region " Consts "

        private const byte MAX_DIFFICULTY = 30;

        #endregion

        #region " Properties "

        /// <summary>
        /// Gets the challenge for the instance.
        /// </summary>
        /// <value>The challenge for the instance.</value>
        public byte[] Challenge
        {
            get { return _challenge; }
        }

        /// <summary>
        /// Gets the value of the solved solution.
        /// </summary>
        /// <value>The solution for the current challenge.</value>
        public byte[] Solution
        {
            get { return _solution; }
        }

        /// <summary>
        /// Gets the difficulty, in bits, for the current challenge.
        /// </summary>
        /// <value>The difficulty, in bits, for the current challenge.</value>
        public byte Difficulty
        {
            get { return _difficulty; }
        }

        /// <summary>
        /// Gets the max difficulty, in bits, that can be used for challenges.
        /// </summary>
        /// <value>The max difficulty, in bits, that can be used for challenges.</value>
        public static byte MaxDifficulty
        {
            get { return MAX_DIFFICULTY; }
        }

        #endregion

        #region " Members "

        private byte[] _solution;
        private byte[] _challenge;
        private byte _difficulty;

        private HashAlgorithm _hash;

        #endregion

        #region " Constructor "

        /// <summary>
        /// Initializes a new instance of the <see cref="HashPuzzle"/> class using the provided hash algorithim, difficulty, and challenge.
        /// </summary>
        /// <param name="hashAlgorithm">The hash implementation to use.</param>
        /// <param name="difficulty">The difficulty of the challenge in bits.</param>
        /// <param name="challenge">The challenge to be solved or null to generate a new one.</param>
        /// <exception cref="ArgumentNullException">The hashAlgorithim is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The difficulty must not exceed 30 bits or the hashAlgorithm size.</exception>
        public HashPuzzle(HashAlgorithmName hashAlgorithm, byte difficulty, byte[] challenge = null)
        {
            if (hashAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(hashAlgorithm));
            }

            Initialize(HashAlgorithm.Create(hashAlgorithm.Name), difficulty, challenge);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HashPuzzle"/> class using the provided hash algorithim, difficulty, and challenge.
        /// </summary>
        /// <param name="hashAlgorithm">The hash implementation to use.</param>
        /// <param name="difficulty">The difficulty of the challenge in bits.</param>
        /// <param name="challenge">The challenge to be solved or null to generate a new one.</param>
        /// <exception cref="ArgumentNullException">The hashAlgorithim is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The difficulty must not exceed 30 bits or the hashAlgorithm size.</exception>
        public HashPuzzle(HashAlgorithm hashAlgorithm, byte difficulty, byte[] challenge = null)
        {
            if (hashAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(hashAlgorithm));
            }

            Initialize(hashAlgorithm, difficulty, challenge);
        }

        private void Initialize(HashAlgorithm hashAlgorithm, byte difficulty, byte[] challenge)
        {
            if (difficulty > MAX_DIFFICULTY || difficulty > hashAlgorithm.HashSize)
            {
                throw new ArgumentOutOfRangeException(nameof(difficulty));
            }

            _hash = hashAlgorithm;
            _difficulty = difficulty;
            _challenge = challenge ?? CreateNonce(16);
        }

        #endregion

        #region " Solution "

        /// <summary>
        /// Returns true and updates the <see cref="Solution"/> property if a solution for the current challenge is found.
        /// </summary>
        /// <returns>True if a solution was found; otherwise, false.</returns>
        public bool FindSolution()
        {
            if (_solution != null)
            {
                return true;
            }

            byte[] hash = null;
            byte[] buffer = new byte[4 + _challenge.Length];

            uint maxCounter = GetMaxCounter(_difficulty);

            Buffer.BlockCopy(_challenge, 0, buffer, 4, _challenge.Length);

            for (uint i = 0; i < maxCounter; i++)
            {
                unsafe
                {
                    fixed (byte* ptr = &buffer[0])
                    {
                        *((uint*)ptr) = i;
                    }
                }

                hash = _hash.ComputeHash(buffer);

                if (CountLeadingZeroBits(hash, _difficulty) >= _difficulty)
                {
                    _solution = new byte[4];
                    Buffer.BlockCopy(buffer, 0, _solution, 0, _solution.Length);

                    return true;
                }
            }

            return false;
        }

        #endregion

        #region " Verification "

        /// <summary>
        /// Returns true if the provided solution is valid for the current challenge and difficulty.
        /// </summary>
        /// <param name="solution">The solution for the current challenge.</param>
        /// <returns>True if the solution is valid; otherwise, false.</returns>
        public bool VerifySolution(byte[] solution)
        {
            if (solution == null)
            {
                throw new ArgumentNullException(nameof(solution));
            }

            if (solution.Length != 4)
            {
                throw new ArgumentOutOfRangeException(nameof(solution));
            }

            byte[] buffer = new byte[solution.Length + _challenge.Length];

            Buffer.BlockCopy(solution, 0, buffer, 0, solution.Length);
            Buffer.BlockCopy(_challenge, 0, buffer, solution.Length, _challenge.Length);

            byte[] hash = _hash.ComputeHash(buffer);

            return CountLeadingZeroBits(hash, _difficulty) >= _difficulty;
        }

        #endregion

        #region " Helpers "

        private static byte[] CreateNonce(int length)
        {
            byte[] nonce = new byte[length];

            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(nonce, 0, nonce.Length - 1);

            return nonce;
        }

        private static uint GetMaxCounter(int bits)
        {
            return (uint)Math.Pow(2, bits) * 3;
        }

        private static int CountLeadingZeroBits(byte[] data, int limit)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            int zeros = 0;
            byte value = 0;

            for (int i = 0; i < data.Length; i++)
            {
                value = data[i];

                if (value == 0)
                {
                    zeros += 8;
                }
                else
                {
                    int count = 1;

                    if (value >> 4 == 0) { count += 4; value <<= 4; }
                    if (value >> 6 == 0) { count += 2; value <<= 2; }

                    zeros += count - (value >> 7);

                    break;
                }

                if (zeros >= limit)
                {
                    break;
                }
            }

            return zeros;
        }

        #endregion

    }

}
