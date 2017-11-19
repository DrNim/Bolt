using System;

namespace Bolt
{
    internal sealed class ClientExchangeFrame : BaseFrame
    {

        private const int STATIC_SIZE = 5;

        public bool IsMutual { get; set; }
        public byte[] Tag { get; set; }
        public byte[] PublicKey { get; set; }
        public byte[] Signature { get; set; } //PublicKey + Client Tag or Nonce, depends if client sent a Tag.

        private byte _publicKeyLength;
        private byte _signatureLength;
        private short _tagLength;

        public ClientExchangeFrame() : base(STATIC_SIZE)
        {
        }

        public override byte[] Serialize()
        {
            int offset = 0;
            byte[] buffer = new byte[STATIC_SIZE + Tag.Length + PublicKey.Length + Signature.Length];
            byte[] tagLength = BitConverter.GetBytes((short)Tag.Length);
 
            buffer[offset++] = (byte)PublicKey.Length;
            buffer[offset++] = (byte)Signature.Length;
            offset += BlockCopy(tagLength, 0, buffer, offset, tagLength.Length);
            buffer[offset++] = IsMutual ? (byte)1 : (byte)0;
            offset += BlockCopy(Tag, 0, buffer, offset, Tag.Length);
            offset += BlockCopy(PublicKey, 0, buffer, offset, PublicKey.Length);
            offset += BlockCopy(Signature, 0, buffer, offset, Signature.Length); 

            return buffer;
        }

        public override int Deserialize(byte[] buffer, int offset, int count)
        { 
            if (InitializeHeader())
            {
                _publicKeyLength = buffer[offset++];
                _signatureLength = buffer[offset++]; 
                _tagLength = BitConverter.ToInt16(buffer, offset);
 
                return _publicKeyLength + _signatureLength + _tagLength;
            }
            else
            {
                offset += 4;

                Tag = new byte[_tagLength];
                PublicKey = new byte[_publicKeyLength];
                Signature = new byte[_signatureLength];

                IsMutual = (buffer[offset++] == 1);
                offset += BlockCopy(buffer, offset, Tag, 0, Tag.Length);
                offset += BlockCopy(buffer, offset, PublicKey, 0, PublicKey.Length);
                offset += BlockCopy(buffer, offset, Signature, 0, Signature.Length);

                return -1;
            }
        }
    }

}