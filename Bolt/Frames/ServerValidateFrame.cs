namespace Bolt
{
    internal sealed class ServerValidateFrame : BaseFrame
    {

        private const int STATIC_SIZE = 2;

        public byte[] PublicKey { get; set; }
        public byte[] Signature { get; set; } //PublicKey + Server Tag

        private byte _publicKeyLength;
        private byte _signatureLength;

        public ServerValidateFrame() : base(STATIC_SIZE)
        {
        }

        public override byte[] Serialize()
        {
            if(Signature == null)
            {
                Signature = new byte[0];
            }

            int offset = 0;
            byte[] buffer = new byte[STATIC_SIZE + PublicKey.Length + Signature.Length];

            buffer[offset++] = (byte)PublicKey.Length;
            buffer[offset++] = (byte)Signature.Length;
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

               return _publicKeyLength + _signatureLength;
            }
            else
            {
                offset += 2;

                PublicKey = new byte[_publicKeyLength];
                Signature = new byte[_signatureLength];

                offset += BlockCopy(buffer, offset, PublicKey, 0, PublicKey.Length);
                offset += BlockCopy(buffer, offset, Signature, 0, Signature.Length);

                return -1;
            }
        }
    }

}