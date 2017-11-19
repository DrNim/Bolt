using System;
using System.Security.Cryptography;

namespace Bolt
{

    //NOTES:
    //AES-CTR specifications (RFC 3686) call for a random 32bit 'Nonce' generated at the start of a session, a 64bit
    //'IV' randomly generated for each 'packet' (a packet being 4294967295 blocks or 64GB), followed by a 32bit 'Counter'
    //starting at 1 and incremented after each counter block is encrypted.

    //This implementation instead consists of a variable length per-packet IV to accomdate algorithims with smaller
    //block sizes, followed by a 32bit counter.
    internal sealed class CounterModeCryptoTransform : ICryptoTransform
    {

        #region " Properties "

        public bool CanReuseTransform
        {
            get { return _transform.CanReuseTransform; }
        }

        public bool CanTransformMultipleBlocks
        {
            get { return _transform.CanTransformMultipleBlocks; }
        }

        public int InputBlockSize
        {
            get { return 1; }
        }

        public int OutputBlockSize
        {
            get { return 1; }
        }

        #endregion

        #region " Members "

        private byte[] _iv;
        private uint _counter;
        private int _blockSize;

        private int _counterSize;
        private int _streamIndex;
        private byte[] _keyStream;
        private byte[] _counterStream;

        private ICryptoTransform _transform;

        #endregion

        #region " Constructor "

        public CounterModeCryptoTransform(ICryptoTransform transform, int blockSize, byte[] iv, uint counter)
        {
            _counter = counter;
            _blockSize = blockSize;
            _transform = transform;

            _iv = WrapBytes(iv, (blockSize - 32) / 8);

            PrepareKeyStream();
            GenerateKeyStream();
        }

        #endregion

        #region " Transform "

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (inputBuffer == null)
            {
                throw new ArgumentNullException(nameof(inputBuffer));
            }
            if (outputBuffer == null)
            {
                throw new ArgumentNullException(nameof(outputBuffer));
            }
            if (inputOffset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(inputOffset));
            }
            if (outputOffset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(outputOffset));
            }
            if (inputCount < 0 || inputCount > inputBuffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(inputCount));
            }
            if (inputBuffer.Length - inputCount < inputOffset)
            {
                throw new ArgumentOutOfRangeException(nameof(inputOffset));
            }
            if (outputBuffer.Length - inputCount < outputOffset)
            {
                throw new ArgumentOutOfRangeException(nameof(outputOffset));
            }

            int chunkSize = 0;
            int bytesTransformed = 0;

            while (bytesTransformed < inputCount)
            {
                chunkSize = Math.Min(inputCount - bytesTransformed, _keyStream.Length - _streamIndex);

                for (int i = 0; i < chunkSize; i++)
                {
                    //TODO: Surely using int / long pointers here would be faster, investigate.
                    outputBuffer[i + bytesTransformed + outputOffset] = (byte)(inputBuffer[i + bytesTransformed + inputOffset] ^ _keyStream[i + _streamIndex]);
                }

                bytesTransformed += chunkSize;

                _streamIndex += chunkSize;
                if (_streamIndex == _keyStream.Length)
                {
                    GenerateKeyStream();
                }
            }

            return bytesTransformed;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputBuffer == null)
            {
                throw new ArgumentNullException(nameof(inputBuffer));
            }
            if (inputOffset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(inputOffset));
            }
            if (inputCount < 0 || inputCount > inputBuffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(inputCount));
            }
            if (inputBuffer.Length - inputCount < inputOffset)
            {
                throw new ArgumentOutOfRangeException(nameof(inputOffset));
            }

            byte[] outputBuffer = new byte[inputCount];

            TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, 0);

            return outputBuffer;
        }

        #endregion

        #region " Key Stream "

        private void PrepareKeyStream()
        {
            int blockSize = _blockSize / 8;
            int bufferSize = Math.Max((1024 / blockSize) * blockSize, blockSize);

            _keyStream = new byte[bufferSize];
            _counterStream = new byte[bufferSize];

            _counterSize = _iv.Length + 4;

            for (int i = 0; i < _counterStream.Length; i += _counterSize)
            {
                Buffer.BlockCopy(_iv, 0, _counterStream, i, _iv.Length);
            }
        }

        private void GenerateKeyStream()
        {

            for (int i = _iv.Length; i < _counterStream.Length; i += _counterSize)
            {
                unsafe
                {
                    fixed (byte* ptr = &_counterStream[i])
                    {
                        *((uint*)ptr) = _counter++;
                    }
                }
            }

            //Throw an exception if we're about to rollover the counter; ideally the instance wouldn't be used to encrypt 
            //more than 100~ MB but if we're approaching the 64GB limit the situation is dire and calls for desparate
            //action.
            if (_counter >= (uint.MaxValue - short.MaxValue))
            {
                throw new InvalidOperationException();
            }

            _streamIndex = 0;
            _transform.TransformBlock(_counterStream, 0, _counterStream.Length, _keyStream, 0);
        }

        #endregion

        #region " Helpers "

        private byte[] WrapBytes(byte[] data, int length)
        {
            byte[] output = new byte[length];

            for (int i = 0; i < data.Length; i++)
            {
                output[i % length] ^= data[i];
            }

            return output;
        }

        #endregion

        #region " IDispose "

        public void Dispose()
        {
            _transform.Dispose();
        }

        #endregion

    }

}
