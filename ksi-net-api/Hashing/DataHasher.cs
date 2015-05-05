using System;
using System.IO;
using Microsoft.Win32.SafeHandles;


namespace Guardtime.KSI.Hashing
{
    public class DataHasher
    {
        private const int DefaultStreamBufferSize = 8192;

        private readonly HashAlgorithm _algorithm;
        private readonly System.Security.Cryptography.HashAlgorithm _messageHasher;
        private DataHash _outputHash;

        public DataHasher(HashAlgorithm algorithm)
        {
            if (algorithm == null)
            {
                throw new ArgumentNullException("algorithm");
            }

            /*
                If an algorithm is given which is not implemented, an illegal argument exception is thrown
                The developer must ensure that only implemented algorithms are used.
             */
            if (algorithm.Status == HashAlgorithm.AlgorithmStatus.NotImplemented)
            {
                throw new ArgumentException("Hash algorithm is not implemented");
            }

            _algorithm = algorithm;

            _messageHasher = System.Security.Cryptography.HashAlgorithm.Create(algorithm.Name);
            if (_messageHasher == null)
            {
                throw new ArgumentException("Hash algorithm not supported: " + algorithm.Name);
            }

            _messageHasher.Initialize();
            
        }

        /**
         * Create new data hasher for the default algorithm.
         */
        public DataHasher() : this(HashAlgorithm.GetByName("DEFAULT")) 
        {

        }

        /**
         * Updates the digest using the specified array of bytes, starting at the specified offset.
         *
         * @param data   the array of bytes.
         * @param offset the offset to start from in the array of bytes.
         * @param length the number of bytes to use, starting at the offset.
         * @return the same DataHasher object for chaining calls
         */
        public DataHasher AddData(byte[] data, int offset, int length) {
            if (_outputHash != null) 
            {
                throw new InvalidOperationException("Output hash has already been calculated");
            }

            if (data == null)
            {
                throw new InvalidOperationException("Invalid data added to hasher: null");
            }

            _messageHasher.TransformBlock(data, offset, length, null, 0);
            return this;
        }

        /**
         * Adds data to the digest using the specified array of bytes, starting at an offset of 0.
         *
         * @param data the array of bytes.
         * @return the same DataHasher object for chaining calls
         */
        public DataHasher AddData(byte[] data) {
            /*
             * TODO: JAVA HAS TO BE CHECKED HERE
             */
            return AddData(data, 0, data.Length);
        }

        /**
         * Adds data to the digest using the specified input stream of bytes, starting at an offset of 0.
         *
         * @param inStream input stream of bytes.
         * @return the same DataHasher object for chaining calls
         * @throws IOException If the first byte cannot be read for any reason other than the end of the
         *                     file, if the input stream has been closed, or if some other I/O error occurs.
         */
        public DataHasher AddData(Stream inStream) {
            return AddData(inStream, DefaultStreamBufferSize);
        }

        /**
         * Adds data to the digest using the specified file, starting at the offset 0.
         *
         * @param fileHandle input file handle.
         * @return the same DataHasher object for chaining calls
         * @throws IOException If the first byte cannot be read for any reason other than the end of the
         *                     file, if the input stream has been closed, or if some other I/O error occurs.
         */
        public DataHasher AddData(SafeFileHandle fileHandle) {
            return AddData(fileHandle, DefaultStreamBufferSize);
        }


        /**
         * Adds data to the digest using the specified input stream of bytes, starting at an offset of 0.
         *
         * @param inStream   input stream of bytes.
         * @param bufferSize maximum allowed buffer size for reading data
         * @return the same DataHasher object for chaining calls
         * @throws IOException If the first byte cannot be read for any reason other than the end of the
         *                     file, if the input stream has been closed, or if some other I/O error occurs.
         */
        public DataHasher AddData(Stream inStream, int bufferSize) {
            if (inStream == null)
            {
                throw new ArgumentException("Invalid inputstream added to hasher: null");
            }

            var buffer = new byte[bufferSize];
            while (true) 
            {
                var bytesRead = inStream.Read(buffer, 0, bufferSize);

                if (bytesRead == 0) 
                {
                    return this;
                }

                AddData(buffer, 0, bytesRead);
            }
        }

        /**
         * Adds data to the digest using the specified file, starting at the offset 0.
         *
         * @param fileHandle       input file handle.
         * @param bufferSize size of buffer for reading data
         * @return the same DataHasher object for chaining calls
         * @throws IOException If the first byte cannot be read for any reason other than the end of the
         *                     file, if the input stream has been closed, or if some other I/O error occurs.
         */
        public DataHasher AddData(SafeFileHandle fileHandle, int bufferSize)
        {
            if (fileHandle == null)
            {
                throw new ArgumentException("Invalid file added to hasher: null");
            }

            using (var inStream = new FileStream(fileHandle, FileAccess.Read))
            {
                return AddData(inStream, bufferSize);
            }
        }


        /**
         * Get the final hash value for the digest.
         * <p>
         * This will not reset hash calculation.
         *
         * @return hashValue with computed hash value.
         *
         */
        public DataHash GetHash() {
            if (_outputHash != null) return _outputHash;
            _messageHasher.TransformFinalBlock(new byte[] { }, 0, 0);
            var hash = _messageHasher.Hash;
            _outputHash = new DataHash(_algorithm, hash);

            return _outputHash;
        }


        /**
         * Resets hash calculation.
         *
         * @return the same DataHasher object for chaining calls
         */
        public DataHasher Reset() {
            _outputHash = null;
            _messageHasher.Clear();
            _messageHasher.Initialize();

            return this;
        }
    }
}
