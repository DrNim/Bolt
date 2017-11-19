namespace Bolt
{
    internal sealed class ServerEchoFrame : BaseFrame
    {
 
        public byte[] Nonce { get; set; } //Encrypted

        public ServerEchoFrame() : base(BoltBase.NONCE_LENGTH)
        {
        }

        public override byte[] Serialize()
        {
            int offset = 0;
            byte[] buffer = new byte[Nonce.Length];

            offset += BlockCopy(Nonce, 0, buffer, offset, Nonce.Length);

            return buffer;
        }

        public override int Deserialize(byte[] buffer, int offset, int count)
        {
            Nonce = new byte[BoltBase.NONCE_LENGTH];

            BlockCopy(buffer, offset, Nonce, 0, Nonce.Length);

            return -1;
        }
    } 

}