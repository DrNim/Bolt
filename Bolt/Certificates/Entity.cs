using System;
using System.IO;
using System.Security.Cryptography;

namespace Bolt
{

    // .csr if PublicOnly, otherwise, .key
    public sealed class Entity : IEquatable<Entity>
    {

        #region " Consts "

        private const byte MIN_VERSION = 1;
        private const byte MAX_VERSION = 1;

        private const int MAX_NAME_LENGTH = 256;
        private const int MAX_EMAIL_LENGTH = 256;
        private const int MAX_COUNTRY_LENGTH = 2;
        private const int MAX_STATE_LENGTH = 128;
        private const int MAX_CITY_LENGTH = 128;
        private const int MAX_ZIP_LENGTH = 40;

        #endregion

        #region " Properties "

        public string EntityName
        {
            get { return _entityName; }
        }

        public string EmailAddress
        {
            get { return _emailAddress; }
        }

        public string CountryOrRegionCode
        {
            get { return _countryOrRegionCode; }
        }

        public string StateOrProvinceName
        {
            get { return _stateOrProvinceName; }
        }

        public string CityOrLocalityName
        {
            get { return _cityOrLocalityName; }
        }

        public string ZipOrPostalCode
        {
            get { return _zipOrPostalCode; }
        }

        public bool PublicOnly
        {
            get { return _publicOnly; }
        }

        public ECDsa Key
        {
            get { return _key; }
        }

        /// <summary>
        /// Gets the public key token, which is the SHA256 hash of the public key from which the entity is derived.
        /// </summary>
        /// <value>A byte array that contains the public key token.</value>
        public byte[] Token
        {
            get { return _token ?? EnsureTokenInitialized(); }
        }

        /// <summary>
        /// Get the format version of the entity.
        /// </summary>
        /// <value>The format version of the entity.</value>
        public byte Version
        {
            get { return _version; }
        }

        #endregion

        #region " Members "

        private string _entityName;
        private string _emailAddress;
        private string _countryOrRegionCode;
        private string _stateOrProvinceName;
        private string _cityOrLocalityName;
        private string _zipOrPostalCode;

        private byte _version;
        private bool _publicOnly;

        private ECDsa _key;
        private byte[] _token;

        #endregion

        #region " Constructor "

        private Entity(ECDsa key, bool publicOnly, byte version, EntityOptions options)
        {
            ValidateOptions(options);

            _key = key;
            _publicOnly = publicOnly;
            _version = version;
            _entityName = options.EntityName;
            _emailAddress = options.EmailAddress;
            _countryOrRegionCode = options.CountryOrRegionCode;
            _stateOrProvinceName = options.StateOrProvinceName;
            _cityOrLocalityName = options.CityOrLocalityName;
            _zipOrPostalCode = options.ZipOrPostalCode;
        }

        #endregion

        #region " Helpers "

        private byte[] EnsureTokenInitialized()
        {
            SHA256 sha256 = SHA256.Create();
            ECParameters parameters = _key.ExportParameters(false);

            sha256.TransformBlock(parameters.Q.X, 0, parameters.Q.X.Length, null, 0);
            sha256.TransformFinalBlock(parameters.Q.Y, 0, parameters.Q.Y.Length);

            _token = sha256.Hash;

            return _token;
        }

        private void ValidateOptions(EntityOptions options)
        {
            if (options.EntityName?.Length > MAX_NAME_LENGTH)
            {
                throw new ArgumentOutOfRangeException(nameof(options.EntityName));
            }

            if (options.EmailAddress?.Length > MAX_EMAIL_LENGTH)
            {
                throw new ArgumentOutOfRangeException(nameof(options.EmailAddress));
            }

            if (options.CountryOrRegionCode?.Length > MAX_COUNTRY_LENGTH)
            {
                throw new ArgumentOutOfRangeException(nameof(options.CountryOrRegionCode));
            }

            if (options.StateOrProvinceName?.Length > MAX_STATE_LENGTH)
            {
                throw new ArgumentOutOfRangeException(nameof(options.StateOrProvinceName));
            }

            if (options.CityOrLocalityName?.Length > MAX_CITY_LENGTH)
            {
                throw new ArgumentOutOfRangeException(nameof(options.CityOrLocalityName));
            }

            if (options.ZipOrPostalCode?.Length > MAX_ZIP_LENGTH)
            {
                throw new ArgumentOutOfRangeException(nameof(options.ZipOrPostalCode));
            }
        }

        private static byte[] DeserializeBytes(BinaryReader reader)
        {
            return reader.ReadBytes(reader.ReadInt32());
        }

        public byte[] Serialize(bool includePrivateParameters)
        {
            if (_publicOnly)
            {
                includePrivateParameters = false;
            }

            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);
            ECParameters parameters = _key.ExportParameters(includePrivateParameters);

            writer.Write(MAX_VERSION);
            writer.Write(_entityName ?? string.Empty);
            writer.Write(_emailAddress ?? string.Empty);
            writer.Write(_countryOrRegionCode ?? string.Empty);
            writer.Write(_stateOrProvinceName ?? string.Empty);
            writer.Write(_cityOrLocalityName ?? string.Empty);
            writer.Write(_zipOrPostalCode ?? string.Empty);
            Serialize(writer, parameters.Q.X);
            Serialize(writer, parameters.Q.Y);
            writer.Write(includePrivateParameters);

            if (includePrivateParameters)
            {
                Serialize(writer, parameters.D);
            }

            return stream.ToArray();
        }

        private void Serialize(BinaryWriter writer, byte[] value)
        {
            writer.Write(value.Length);
            writer.Write(value);
        }

        #endregion

        #region " Factory "

        public static Entity Create(EntityOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            return new Entity(ECDsa.Create(ECCurve.NamedCurves.nistP521), false, MAX_VERSION, options);
        }

        public static Entity Deserialize(byte[] buffer)
        {
            return Deserialize(buffer, 0, buffer.Length);
        }

        public static Entity Deserialize(byte[] buffer, int offset, int count)
        {
            MemoryStream stream = new MemoryStream(buffer, offset, count);
            BinaryReader reader = new BinaryReader(stream);
            EntityOptions options = new EntityOptions();
            ECParameters parameters = new ECParameters();

            byte version = reader.ReadByte();

            if (version < MIN_VERSION || version > MAX_VERSION)
            {
                throw new InvalidOperationException("Invalid format version.");
            }

            options.EntityName = reader.ReadString();
            options.EmailAddress = reader.ReadString();
            options.CountryOrRegionCode = reader.ReadString();
            options.StateOrProvinceName = reader.ReadString();
            options.CityOrLocalityName = reader.ReadString();
            options.ZipOrPostalCode = reader.ReadString();

            parameters.Curve = ECCurve.NamedCurves.nistP521;
            parameters.Q.X = DeserializeBytes(reader);
            parameters.Q.Y = DeserializeBytes(reader);

            bool hasPrivateParameters = reader.ReadBoolean();

            if (hasPrivateParameters)
            {
                parameters.D = DeserializeBytes(reader);
            }

            return new Entity(ECDsa.Create(parameters), !hasPrivateParameters, version, options);
        }

        #endregion

        #region " IEquatable "

        /// <summary>
        /// Returns a value that indicates whether two <see cref="Entity"/> instances are equal.
        /// </summary>
        /// <param name="other">The object to compare with the current instance.</param>
        public bool Equals(Entity other)
        {
            for (int i = 0; i < Token.Length; i++)
            {
                if (Token[i] != other.Token[i])
                {
                    return false;
                }
            }

            return true;
        }

        #endregion

    }

}