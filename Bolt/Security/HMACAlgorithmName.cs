using System;

namespace Bolt
{

    /// <summary>
    /// Specifies the name of a cryptographic HMAC algorithm.
    /// </summary>
    public struct HMACAlgorithmName : IEquatable<HMACAlgorithmName>
    {
        #region " Members "

        private readonly string _name;

        #endregion

        #region " Properties "

        /// <summary>
        /// Gets the underlying string representation of the algorithm name.
        /// </summary>
        /// <value>The string representation of the algorithm name, or null or <see cref="String.Empty"/> if no hash algorithm is available.</value>
        public string Name
        {
            get { return _name; }
        }

        /// <summary>
        /// Gets a HMAC algorithm name that represents "MD5".
        /// </summary>
        /// <value>A HMAC algorithm name that represents "MD5".</value>
        public static HMACAlgorithmName HMACMD5
        {
            get { return new HMACAlgorithmName("HMACMD5"); }
        }

        /// <summary>
        /// Gets a HMAC algorithm name that represents "HMACRIPEMD160".
        /// </summary>
        /// <value>A HMAC algorithm name that represents "HMACRIPEMD160".</value>
        public static HMACAlgorithmName HMACRIPEMD160
        {
            get { return new HMACAlgorithmName("HMACRIPEMD160"); }
        }

        /// <summary>
        /// Gets a HMAC algorithm name that represents "HMACSHA1".
        /// </summary>
        /// <value>A HMAC algorithm name that represents "HMACSHA1".</value>
        public static HMACAlgorithmName HMACSHA1
        {
            get { return new HMACAlgorithmName("HMACSHA1"); }
        }

        /// <summary>
        /// Gets a HMAC algorithm name that represents "HMACSHA256".
        /// </summary>
        /// <value>A HMAC algorithm name that represents "HMACSHA256".</value>
        public static HMACAlgorithmName HMACSHA256
        {
            get { return new HMACAlgorithmName("HMACSHA256"); }
        }

        /// <summary>
        /// Gets a HMAC algorithm name that represents "HMACSHA384".
        /// </summary>
        /// <value>A HMAC algorithm name that represents "HMACSHA384".</value>
        public static HMACAlgorithmName HMACSHA384
        {
            get { return new HMACAlgorithmName("HMACSHA384"); }
        }

        /// <summary>
        /// Gets a HMAC algorithm name that represents "HMACSHA512".
        /// </summary>
        /// <value>A HMAC algorithm name that represents "HMACSHA512".</value>
        public static HMACAlgorithmName HMACSHA512
        {
            get { return new HMACAlgorithmName("HMACSHA512"); }
        }

        /// <summary>
        /// Gets a HMAC algorithm name that represents "MACTripleDES".
        /// </summary>
        /// <value>A HMAC algorithm name that represents "MACTripleDES".</value>
        public static HMACAlgorithmName MACTripleDES
        {
            get { return new HMACAlgorithmName("MACTripleDES"); }
        }

        #endregion

        #region " Constructor "

        /// <summary>
        /// Initializes a new instance of the <see cref="HMACAlgorithmName"/> structure with a custom name.
        /// </summary>
        /// <param name="name">The custom HMAC algorithm name.</param>
        public HMACAlgorithmName(string name)
        {
            _name = name;
        }

        #endregion

        #region " Overrides "

        /// <summary>
        /// Returns a value that indicates whether the current instance and a specified object are equal.
        /// </summary>
        /// <param name="obj">The object to compare with the current instance.</param>
        /// <returns>true if obj is a <see cref="HMACAlgorithmName"/> object and its <see cref="Name"/> property is equal to that of the current instance. The comparison is ordinal and case-sensitive.</returns>
        public override bool Equals(object obj)
        {
            if (!(obj is HMACAlgorithmName))
            {
                return false;
            }

            return Equals((HMACAlgorithmName)obj);
        }

        /// <summary>
        /// Returns the hash code for the current instance.
        /// </summary>
        /// <returns>The hash code for the current instance, or 0 if no name value was supplied to the <see cref="HMACAlgorithmName"/> constructor.</returns>
        public override int GetHashCode()
        {
            if (_name == null)
            {
                return 0;
            }

            return _name.GetHashCode();
        }

        /// <summary>
        /// Returns the string representation of the current <see cref="HMACAlgorithmName"/> instance.
        /// </summary>
        /// <returns>The string representation of the current <see cref="HMACAlgorithmName"/> instance.</returns>
        public override string ToString()
        {
            return _name ?? string.Empty;
        }

        #endregion

        #region " IEquatable "

        /// <summary>
        /// Returns a value that indicates whether two <see cref="HMACAlgorithmName"/> instances are equal.
        /// </summary>
        /// <param name="other">The object to compare with the current instance.</param>
        /// <returns>true if the <see cref="Name"/> property of other is equal to that of the current instance. The comparison is ordinal and case-sensitive.</returns>
        public bool Equals(HMACAlgorithmName other)
        {
            return _name == other.Name;
        }

        #endregion

    }

}
