using System;
using System.IO;
using System.Security.Cryptography;

namespace Bolt
{

    //.cer
    public sealed class Tag
    {

        #region " Consts "

        private const byte MIN_VERSION = 1;
        private const byte MAX_VERSION = 1;

        private const int MAX_QUALIFIER_LENGTH = 64;

        #endregion

        #region " Properties "

        /// <summary>
        /// Gets the qualifier of the tag.
        /// </summary>
        /// <value>The qualifier of the tag.</value>
        public string Qualifier
        {
            get { return _qualifier; }
        }

        /// <summary>
        /// Gets the serial number of the tag.
        /// </summary>
        /// <value>The serial number of the tag.</value>
        public Guid SerialNumber
        {
            get { return _serialNumber; }
        }

        /// <summary>
        /// Gets the date in local time on which the tag becomes valid.
        /// </summary>
        /// <value>A <see cref="DateTime"/> object that represents the effective date of the tag.</value>
        public DateTime NotBefore
        {
            get { return _notBefore; }
        }

        /// <summary>
        /// Gets the date in local time after which the tage is no longer valid.
        /// </summary>
        /// <value>A <see cref="DateTime"/> object that represents the expiration date for the tag.</value>
        public DateTime NotAfter
        {
            get { return _notAfter; }
        }

        /// <summary>
        /// Gets the holder of the tag.
        /// </summary>
        /// <value>A <see cref="Entity"/> object that represents the holder of the tag.</value>
        public Entity Holder
        {
            get { return _holder; }
        }

        /// <summary>
        /// Gets the issuer of the tag.
        /// </summary>
        /// <value>A <see cref="Entity"/> object that represents the issuer of the tag.</value>
        public Entity Issuer
        {
            get { return _issuer; }
        }

        /// <summary>
        /// Get the format version of the tag.
        /// </summary>
        /// <value>The format version of the tag.</value>
        public byte Version
        {
            get { return _version; }
        }

        public byte[] RawData
        {
            get { return _rawData ?? EnsureRawDataInitialized(); }
        }

        #endregion

        #region " Members "

        private string _qualifier;
        private Guid _serialNumber;
        private DateTime _notAfter;
        private DateTime _notBefore;
        private Entity _holder;
        private Entity _issuer;

        private byte _version;
        private byte[] _rawData;
        private byte[] _signature;

        #endregion

        #region " Constructor "

        private Tag(Entity issuer, Entity holder, byte version, byte[] rawData, byte[] signature, TagOptions options)
        {
            ValidateOptions(options);

            _issuer = issuer;
            _holder = holder;
            _version = version;
            _qualifier = options.Qualifier;
            _serialNumber = options.SerialNumber;
            _notAfter = options.NotAfter;
            _notBefore = options.NotBefore;
            _rawData = rawData;
            _signature = signature;
        }

        #endregion

        #region " Verification "

        public bool Verify(EntityCollection trustedIssuers)
        {
            if (_notBefore > DateTime.Now || _notAfter < DateTime.Now)
            {
                return false;
            }

            if (!trustedIssuers.Contains(_issuer))
            {
                return false;
            }

            if (_rawData == null)
            {
                EnsureRawDataInitialized();
            }

            return _issuer.Key.VerifyData(_rawData, 0, _rawData.Length - _signature.Length - 4, _signature, HashAlgorithmName.SHA256);
        }

        #endregion

        #region " Helpers "

        private void ValidateOptions(TagOptions options)
        {
            if (options.Qualifier?.Length > MAX_QUALIFIER_LENGTH)
            {
                throw new ArgumentOutOfRangeException(nameof(options.Qualifier));
            }
        }

        private static byte[] DeserializeBytes(BinaryReader reader)
        {
            return reader.ReadBytes(reader.ReadInt32());
        }

        private byte[] EnsureRawDataInitialized()
        {
            bool isRoot = (_issuer == _holder);

            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(MAX_VERSION);
            writer.Write(_notBefore.ToBinary());
            writer.Write(_notAfter.ToBinary());
            writer.Write(_serialNumber.ToByteArray());
            writer.Write(_qualifier ?? string.Empty);
            writer.Write(isRoot);
            Serialize(writer, _issuer.Serialize(false));

            if (!isRoot)
            {
                Serialize(writer, _holder.Serialize(false));
            }

            stream.Position = 0;

            _signature = _issuer.Key.SignData(stream, HashAlgorithmName.SHA256);
            Serialize(writer, _signature);
            _rawData = stream.ToArray();

            return _rawData;
        }

        private void Serialize(BinaryWriter writer, byte[] value)
        {
            writer.Write(value.Length);
            writer.Write(value);
        }

        #endregion

        #region " Factory "

        public static Tag Create(Entity issuer, Entity holder, TagOptions options)
        {
            if (issuer == null)
            {
                throw new ArgumentNullException(nameof(issuer));
            }

            if (holder == null)
            {
                throw new ArgumentNullException(nameof(holder));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (issuer.PublicOnly)
            {
                throw new ArgumentException("Entity must contain a private key.", nameof(issuer));
            }

            return new Tag(issuer, holder, MAX_VERSION, null, null, options);
        }

        public static Tag Deserialize(byte[] buffer)
        {
            return Deserialize(buffer, 0, buffer.Length);
        }

        public static Tag Deserialize(byte[] buffer, int offset, int count)
        {
            MemoryStream stream = new MemoryStream(buffer, offset, count);
            BinaryReader reader = new BinaryReader(stream);
            TagOptions options = new TagOptions();

            byte version = reader.ReadByte();

            if (version < MIN_VERSION || version > MAX_VERSION)
            {
                throw new InvalidOperationException("Invalid format version.");
            }

            options.NotBefore = DateTime.FromBinary(reader.ReadInt64());
            options.NotAfter = DateTime.FromBinary(reader.ReadInt64());
            options.SerialNumber = new Guid(reader.ReadBytes(16));
            options.Qualifier = reader.ReadString();

            bool isRoot = reader.ReadBoolean();

            Entity issuer = Entity.Deserialize(DeserializeBytes(reader));
            Entity holder = isRoot ? issuer : Entity.Deserialize(DeserializeBytes(reader));

            byte[] signature = DeserializeBytes(reader);

            return new Tag(issuer, holder, version, stream.ToArray(), signature, options);
        }

        #endregion

    }

}