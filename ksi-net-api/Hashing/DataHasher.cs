using System.Collections.Generic;
using System.IO;
using Guardtime.KSI.Exceptions;
using Microsoft.Win32.SafeHandles;

namespace Guardtime.KSI.Hashing
{
    /// <summary>
    ///     This class provides functionality for hashing data.
    /// </summary>
    public class DataHasher
    {
        private const int DefaultStreamBufferSize = 8192;

        private readonly HashAlgorithm _algorithm;
        private System.Security.Cryptography.HashAlgorithm _messageHasher;
        private DataHash _outputHash;

        /// <summary>
        ///     Create new Datahasher with given algorithm
        /// </summary>
        /// <param name="algorithm">Hash algorithm</param>
        /// <exception cref="HashingException">thrown when hasher input data is invalid or hasher could not be created</exception>
        public DataHasher(HashAlgorithm algorithm)
        {
            if (algorithm == null)
            {
                throw new HashingException("Hash algorithm cannot be null.");
            }

            /*
                If an algorithm is given which is not implemented, an illegal argument exception is thrown
                The developer must ensure that only implemented algorithms are used.
             */
            if (algorithm.Status == HashAlgorithm.AlgorithmStatus.NotImplemented)
            {
                throw new HashingException("Hash algorithm is not implemented.");
            }

            _algorithm = algorithm;

            _messageHasher = System.Security.Cryptography.HashAlgorithm.Create(algorithm.Name);
            if (_messageHasher == null)
            {
                throw new HashingException("Hash algorithm(" + algorithm.Name + ") is not supported.");
            }

            _messageHasher.Initialize();
        }

        /// <summary>
        ///     Create new data hasher for the default algorithm.
        /// </summary>
        public DataHasher() : this(HashAlgorithm.GetByName("DEFAULT"))
        {
        }

        /// <summary>
        ///     Updates the digest using the specified array of bytes, starting at the specified offset.
        /// </summary>
        /// <param name="data">the list of bytes.</param>
        /// <param name="offset">the offset to start from in the array of bytes.</param>
        /// <param name="length">the number of bytes to use, starting at the offset.</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        /// <exception cref="HashingException">thrown when hash is already calculated or data is invalid</exception>
        public DataHasher AddData(byte[] data, int offset, int length)
        {
            if (_outputHash != null)
            {
                throw new HashingException("Output hash has already been calculated.");
            }

            if (data == null)
            {
                throw new HashingException("Input data cannot be null.");
            }

            _messageHasher.TransformBlock(data, offset, length, null, 0);
            return this;
        }

        /// <summary>
        ///     Adds data to the digest using the specified array of bytes, starting at an offset of 0.
        /// </summary>
        /// <param name="data">list of bytes</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        /// <exception cref="HashingException">thrown when data is invalid</exception>
        public DataHasher AddData(byte[] data)
        {
            if (data == null)
            {
                throw new HashingException("Input data cannot be null.");
            }

            return AddData(data, 0, data.Length);
        }

        /// <summary>
        ///     Adds data to the digest using the specified collection of bytes, starting at an offset of 0.
        /// </summary>
        /// <param name="data">collection of bytes</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        /// <exception cref="HashingException">thrown when input data is invalid</exception>
        public DataHasher AddData(ICollection<byte> data)
        {
            if (data == null)
            {
                throw new HashingException("Input data cannot be null.");
            }

            byte[] bytes = new byte[data.Count];
            data.CopyTo(bytes, 0);
            return AddData(bytes, 0, bytes.Length);
        }

        /// <summary>
        ///     Adds data to the digest using the specified input stream of bytes, starting at an offset of 0.
        /// </summary>
        /// <param name="inStream">input stream of bytes.</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        /// <exception cref="HashingException">thrown when invalid stream is supplied</exception>
        public DataHasher AddData(Stream inStream)
        {
            return AddData(inStream, DefaultStreamBufferSize);
        }

        /// <summary>
        ///     Adds data to the digest using the specified file, starting at the offset 0.
        /// </summary>
        /// <param name="fileHandle">input file handle.</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        /// <exception cref="HashingException">thrown when invalid file handle is supplied</exception>
        public DataHasher AddData(SafeFileHandle fileHandle)
        {
            return AddData(fileHandle, DefaultStreamBufferSize);
        }

        /// <summary>
        ///     Adds data to the digest using the specified input stream of bytes, starting at an offset of 0.
        /// </summary>
        /// <param name="inStream">input stream of bytes.</param>
        /// <param name="bufferSize">maximum allowed buffer size for reading data</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        /// <exception cref="HashingException">thrown when invalid stream is supplied</exception>
        public DataHasher AddData(Stream inStream, int bufferSize)
        {
            if (inStream == null)
            {
                throw new HashingException("Input stream cannot be null.");
            }

            byte[] buffer = new byte[bufferSize];
            while (true)
            {
                int bytesRead = inStream.Read(buffer, 0, bufferSize);

                if (bytesRead == 0)
                {
                    return this;
                }

                AddData(buffer, 0, bytesRead);
            }
        }

        /// <summary>
        ///     Adds data to the digest using the specified file, starting at the offset 0.
        /// </summary>
        /// <param name="fileHandle">input file handle.</param>
        /// <param name="bufferSize">size of buffer for reading data</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        /// <exception cref="HashingException">thrown when invalid file handle is supplied</exception>
        public DataHasher AddData(SafeFileHandle fileHandle, int bufferSize)
        {
            if (fileHandle == null)
            {
                throw new HashingException("File handle cannot be null.");
            }

            using (FileStream inStream = new FileStream(fileHandle, FileAccess.Read))
            {
                return AddData(inStream, bufferSize);
            }
        }

        /// <summary>
        ///     Get the final hash value for the digest.
        ///     This will not reset hash calculation.
        /// </summary>
        /// <returns>calculated hash</returns>
        public DataHash GetHash()
        {
            if (_outputHash != null) return _outputHash;
            _messageHasher.TransformFinalBlock(new byte[] {}, 0, 0);
            byte[] hash = _messageHasher.Hash;
            _outputHash = new DataHash(_algorithm, hash);

            return _outputHash;
        }

        /// <summary>
        ///     Resets hash calculation.
        /// </summary>
        /// <returns>the same DataHasher object for chaining calls</returns>
        public DataHasher Reset()
        {
            _outputHash = null;
            _messageHasher.Clear();
            _messageHasher = System.Security.Cryptography.HashAlgorithm.Create(_algorithm.Name);

            return this;
        }
    }
}