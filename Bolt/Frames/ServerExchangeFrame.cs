using System;

namespace Bolt
{
    internal sealed class ServerExchangeFrame : BaseFrame
    {
        private const int STATIC_SIZE = 3 + BoltBase.SOLUTION_LENGTH + BoltBase.NONCE_LENGTH;

        public bool Success { get; set; }
        public byte[] Solution { get; set; }
        public byte[] Nonce { get; set; }
        public byte[] Tag { get; set; }

        private short _tagLength;

        public ServerExchangeFrame() : base(STATIC_SIZE)
        {
        }

        public override byte[] Serialize()
        {
            if (Solution == null)
            {
                Solution = new byte[BoltBase.SOLUTION_LENGTH];
            }

            if (Nonce == null)
            {
                Nonce = new byte[BoltBase.NONCE_LENGTH];
            }

            if (Tag == null)
            {
                Tag = new byte[0];
            }

            int offset = 0;
            byte[] buffer = new byte[STATIC_SIZE + Tag.Length];
            byte[] tagLength = BitConverter.GetBytes((short)Tag.Length);

            offset += BlockCopy(tagLength, 0, buffer, offset, tagLength.Length);
            buffer[offset++] = Success ? (byte)1 : (byte)0;
            offset += BlockCopy(Solution, 0, buffer, offset, Solution.Length);
            offset += BlockCopy(Nonce, 0, buffer, offset, Nonce.Length);
            offset += BlockCopy(Tag, 0, buffer, offset, Tag.Length);

            return buffer;
        }

        public override int Deserialize(byte[] buffer, int offset, int count)
        {
            if (InitializeHeader())
            {
                _tagLength = BitConverter.ToInt16(buffer, offset);

                return _tagLength;
            }
            else
            {
                offset += 2;

                Tag = new byte[_tagLength];
                Nonce = new byte[BoltBase.NONCE_LENGTH];
                Solution = new byte[BoltBase.SOLUTION_LENGTH];

                Success = (buffer[offset++] == 1);
                offset += BlockCopy(buffer, offset, Solution, 0, Solution.Length);
                offset += BlockCopy(buffer, offset, Nonce, 0, Nonce.Length);
                offset += BlockCopy(buffer, offset, Tag, 0, Tag.Length);

                return -1;
            }
        }
    }

}