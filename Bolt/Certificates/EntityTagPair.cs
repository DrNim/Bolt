using System;
using System.IO;

namespace Bolt
{

    // .pfx
    public sealed class EntityTagPair
    {

        #region " Properties "

        public Tag Tag
        {
            get { return _tag; }
        }

        /// <summary>
        /// Gets the holder of the tag.
        /// </summary>
        /// <value>A <see cref="Entity"/> object that represents the holder of the tag.</value>
        public Entity Holder
        {
            get { return _holder; }
        }

        #endregion

        #region " Members "

        private Tag _tag;
        private Entity _holder;

        #endregion

        #region " Constructor "

        private EntityTagPair(Tag tag, Entity holder)
        {
            if (tag.Holder != holder)
            {
                throw new ArgumentException("Tag holder mismatch.");
            }

            _tag = tag;
            _holder = holder;
        }

        #endregion

        #region " Helpers "

        private static byte[] DeserializeBytes(BinaryReader reader)
        {
            return reader.ReadBytes(reader.ReadInt32());
        }

        private void Serialize(BinaryWriter writer, byte[] value)
        {
            writer.Write(value.Length);
            writer.Write(value);
        }

        public byte[] Serialize()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            Serialize(writer, _tag.RawData);
            Serialize(writer, _holder.Serialize(true));

            return stream.ToArray();
        }

        #endregion

        #region " Factory "

        public static EntityTagPair Create(Tag tag, Entity holder)
        {
            if (tag == null)
            {
                throw new ArgumentNullException(nameof(tag));
            }

            if (holder == null)
            {
                throw new ArgumentNullException(nameof(holder));
            }

            if (holder.PublicOnly)
            {
                throw new ArgumentException("Entity must contain a private key.", nameof(holder));
            }

            return new EntityTagPair(tag, holder);
        }

        public static EntityTagPair Deserialize(byte[] buffer)
        {
            return Deserialize(buffer, 0, buffer.Length);
        }

        public static EntityTagPair Deserialize(byte[] buffer, int offset, int count)
        {
            MemoryStream stream = new MemoryStream(buffer, offset, count);
            BinaryReader reader = new BinaryReader(stream);

            Tag tag = Tag.Deserialize(DeserializeBytes(reader));
            Entity holder = Entity.Deserialize(DeserializeBytes(reader));

            return new EntityTagPair(tag, holder);
        }

        #endregion

    }

}