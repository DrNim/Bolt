using System;

namespace Bolt
{

    public sealed class DataEncodedEventArgs : EventArgs
    {
        #region " Properties "

        public byte[] Header
        {
            get { return _header; }
        }

        public byte[] Buffer
        {
            get { return _buffer; }
        }

        public int Count
        {
            get { return _count; }
        }

        public int Offset
        {
            get { return _offset; }
        }

        #endregion

        #region " Members "

        private int _count;
        private int _offset;

        private byte[] _buffer;
        private byte[] _header;

        #endregion

        #region " Constructor "

        public DataEncodedEventArgs(byte[] buffer, int offset, int count, byte[] header)
        {
            _buffer = buffer;
            _offset = offset;
            _count = count;
            _header = header;
        }

        #endregion
    }

}