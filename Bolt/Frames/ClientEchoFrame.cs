namespace Bolt
{
    internal sealed class ClientEchoFrame : BaseFrame
    {

        public byte[] ClientNonce { get; set; } //Encrypted
        public byte[] ServerNonce { get; set; } //Encrypted

        public ClientEchoFrame() : base(BoltBase.NONCE_LENGTH * 2)
        {
        }

        public override byte[] Serialize()
        {
            int offset = 0;
            byte[] buffer = new byte[ClientNonce.Length + ServerNonce.Length];

            offset += BlockCopy(ClientNonce, 0, buffer, offset, ClientNonce.Length);
            offset += BlockCopy(ServerNonce, 0, buffer, offset, ServerNonce.Length);

            return buffer;
        }

        public override int Deserialize(byte[] buffer, int offset, int count)
        { 
            ClientNonce = new byte[BoltBase.NONCE_LENGTH];
            ServerNonce = new byte[BoltBase.NONCE_LENGTH];

            offset += BlockCopy(buffer, offset, ClientNonce, 0, ClientNonce.Length);
            offset += BlockCopy(buffer, offset, ServerNonce, 0, ServerNonce.Length);

            return -1;
        }
    }

}