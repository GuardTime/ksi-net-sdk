﻿/*
 * Copyright 2013-2018 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

using System;
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Org.BouncyCastle.Crypto;

namespace Guardtime.KSI.Crypto.BouncyCastle.Hashing
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
        public DataHasher(HashAlgorithm algorithm)
        {
            if (algorithm == null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            _algorithm = algorithm;
            _digester = DigestProvider.GetDigest(algorithm);
        }

        /// <summary>
        ///     Updates the digest using the specified array of bytes, starting at the specified offset.
        /// </summary>
        /// <param name="data">the list of bytes.</param>
        /// <param name="offset">the offset to start from in the array of bytes.</param>
        /// <param name="length">the number of bytes to use, starting at the offset.</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        public IDataHasher AddData(byte[] data, int offset, int length)
        {
            if (_outputHash != null)
            {
                throw new HashingException("Output hash has already been calculated.");
            }

            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            _digester.BlockUpdate(data, offset, length);
            return this;
        }

        /// <summary>
        ///     Adds data to the digest using the specified array of bytes, starting at an offset of 0.
        /// </summary>
        /// <param name="data">list of bytes</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        public IDataHasher AddData(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            return AddData(data, 0, data.Length);
        }

        /// <summary>
        ///     Adds data to the digest using the specified input stream of bytes, starting at an offset of 0.
        /// </summary>
        /// <param name="inStream">input stream of bytes.</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
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
        public IDataHasher AddData(Stream inStream, int bufferSize)
        {
            if (inStream == null)
            {
                throw new ArgumentNullException(nameof(inStream));
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