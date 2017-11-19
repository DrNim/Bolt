namespace Bolt
{
    internal sealed class ServerNegotiateFrame : BaseFrame
    {
        private const int STATIC_SIZE = 2;

        public byte MinVersion { get; set; }
        public byte MaxVersion { get; set; }

        public ServerNegotiateFrame() : base(STATIC_SIZE)
        {
        }

        public override byte[] Serialize()
        {
            int offset = 0;
            byte[] buffer = new byte[STATIC_SIZE];

            buffer[offset++] = MinVersion;
            buffer[offset++] = MaxVersion;

            return buffer;
        }

        public override int Deserialize(byte[] buffer, int offset, int count)
        { 
            MinVersion = buffer[offset++];
            MaxVersion = buffer[offset++];

            return -1;
        }
    }

}