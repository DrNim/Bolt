namespace Bolt
{
    internal sealed class ClientNegotiateFrame : BaseFrame
    {
        private const int STATIC_SIZE = 4 + BoltBase.NONCE_LENGTH;

        public byte MinVersion { get; set; }
        public byte MaxVersion { get; set; }
        public bool IsMutual { get; set; } 
        public byte Difficulty { get; set; }
        public byte[] Nonce { get; set; }

        public ClientNegotiateFrame() : base(STATIC_SIZE)
        {
        }

        public override byte[] Serialize()
        {
            int offset = 0;
            byte[] buffer = new byte[STATIC_SIZE];

            buffer[offset++] = MinVersion;
            buffer[offset++] = MaxVersion;
            buffer[offset++] = IsMutual ? (byte)1 : (byte)0; 
            buffer[offset++] = Difficulty;
            offset += BlockCopy(Nonce, 0, buffer, offset, Nonce.Length);

            return buffer;
        }

        public override int Deserialize(byte[] buffer, int offset, int count)
        { 
            Nonce = new byte[BoltBase.NONCE_LENGTH];

            MinVersion = buffer[offset++];
            MaxVersion = buffer[offset++];
            IsMutual = (buffer[offset++] == 1);
            Difficulty = buffer[offset++];
            offset += BlockCopy(buffer, offset, Nonce, 0, Nonce.Length);

            return -1;
        }
    }

}