using System;

namespace Bolt
{
    internal abstract class BaseFrame
    {

        #region " Properties "

        public int InitialSize
        {
            get { return _initialSize; } 
        }

        #endregion

        #region " Members "

        private bool _hasHeader;
        private int _initialSize;
   
        #endregion

        #region " Constructor "

        protected BaseFrame(int initialSize) 
        {
            _initialSize = initialSize;
        } 

        #endregion
 
        #region " Helpers "

        protected bool InitializeHeader()
        {
            if (_hasHeader)
            {
                return false;
            }

            _hasHeader = true;
            return true;
        }

        protected static int BlockCopy(byte[] src, int srcOffset, byte[] dst, int dstOffset, int count)
        {
            Buffer.BlockCopy(src, srcOffset, dst, dstOffset, count);

            return count;
        }

        #endregion

        #region " Serialization "

        public abstract byte[] Serialize();

        public abstract int Deserialize(byte[] buffer, int offset, int count);

        #endregion

    }

}