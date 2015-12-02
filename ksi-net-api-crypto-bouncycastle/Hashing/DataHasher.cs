using System;
using System.Collections.Generic;
using System.IO;
using Guardtime.KSI.Exceptions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Security;

namespace Guardtime.KSI.Hashing
{
    /// <summary>
    ///     This class provides functionality for hashing data.
    /// </summary>
    public class DataHasher : IDataHasher
    {
        private const int DefaultStreamBufferSize = 8192;

        private readonly HashAlgorithm _algorithm;
        private readonly IDigest _digester;
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
                throw new HashingException("Invalid hash algorithm: null.");
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

            try
            {
                _digester = DigestUtilities.GetDigest(algorithm.Name);
            }
            catch (SecurityUtilityException e)
            {
                throw new HashingException("Hash algorithm(" + algorithm.Name + ") is not supported.", e);
            }
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
        public IDataHasher AddData(byte[] data, int offset, int length)
        {
            if (_outputHash != null)
            {
                throw new HashingException("Output hash has already been calculated.");
            }

            if (data == null)
            {
                throw new HashingException("Invalid input data: null.");
            }

            _digester.BlockUpdate(data, offset, length);
            return this;
        }

        /// <summary>
        ///     Adds data to the digest using the specified array of bytes, starting at an offset of 0.
        /// </summary>
        /// <param name="data">list of bytes</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        /// <exception cref="HashingException">thrown when data is invalid</exception>
        public IDataHasher AddData(byte[] data)
        {
            if (data == null)
            {
                throw new HashingException("Invalid input data: null.");
            }

            return AddData(data, 0, data.Length);
        }


        /// <summary>
        ///     Adds data to the digest using the specified input stream of bytes, starting at an offset of 0.
        /// </summary>
        /// <param name="inStream">input stream of bytes.</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        /// <exception cref="HashingException">thrown when invalid stream is supplied</exception>
        public IDataHasher AddData(Stream inStream)
        {
            return AddData(inStream, DefaultStreamBufferSize);
        }

        /// <summary>
        ///     Adds data to the digest using the specified input stream of bytes, starting at an offset of 0.
        /// </summary>
        /// <param name="inStream">input stream of bytes.</param>
        /// <param name="bufferSize">maximum allowed buffer size for reading data</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        /// <exception cref="HashingException">thrown when invalid stream is supplied</exception>
        public IDataHasher AddData(Stream inStream, int bufferSize)
        {
            if (inStream == null)
            {
                throw new HashingException("Invalid input stream: null.");
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
        ///     Get the final hash value for the digest.
        ///     This will not reset hash calculation.
        /// </summary>
        /// <returns>calculated hash</returns>
        public DataHash GetHash()
        {
            if (_outputHash != null)
            {
                return _outputHash;
            }

            // TODO: Should check the length?
            byte[] hash = new byte[_algorithm.Length];
            _digester.DoFinal(hash, 0);
            _outputHash = new DataHash(_algorithm, hash);

            return _outputHash;
        }

        /// <summary>
        ///     Resets hash calculation.
        /// </summary>
        /// <returns>the same DataHasher object for chaining calls</returns>
        public IDataHasher Reset()
        {
            _outputHash = null;
            _digester.Reset();

            return this;
        }

    }
}