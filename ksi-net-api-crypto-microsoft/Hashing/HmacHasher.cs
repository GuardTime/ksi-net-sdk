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
using System.Security.Cryptography;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using HashAlgorithm = Guardtime.KSI.Hashing.HashAlgorithm;

namespace Guardtime.KSI.Crypto.Microsoft.Hashing
{
    /// <summary>
    /// HMAC hasher
    /// </summary>
    public class HmacHasher : IHmacHasher
    {
        private readonly HashAlgorithm _algorithm;

        /// <summary>
        /// Create new HmacHasher with given algorithm
        /// </summary>
        /// <param name="algorithm">HMAC algorithm</param>
        public HmacHasher(HashAlgorithm algorithm)
        {
            _algorithm = algorithm;
        }

        /// <summary>
        ///     Calculate HMAC for data with given key.
        /// </summary>
        /// <param name="key">HMAC key</param>
        /// <param name="data">data to calculate HMAC from</param>
        /// <returns>HMAC data hash</returns>
        public DataHash GetHash(byte[] key, byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            return new DataHash(_algorithm, GetHasher(_algorithm, key).ComputeHash(data));
        }

        private static HMAC GetHasher(HashAlgorithm hmacAlgorithm, byte[] key)
        {
            if (hmacAlgorithm == HashAlgorithm.Sha1)
            {
                return new HMACSHA1(key);
            }
            if (hmacAlgorithm == HashAlgorithm.Sha2256)
            {
                return new HMACSHA256(key);
            }
            if (hmacAlgorithm == HashAlgorithm.Ripemd160)
            {
                return new HMACRIPEMD160(key);
            }
            if (hmacAlgorithm == HashAlgorithm.Sha2384)
            {
                return new HMACSHA384(key);
            }
            if (hmacAlgorithm == HashAlgorithm.Sha2512)
            {
                return new HMACSHA512(key);
            }
            throw new HashingException("Hash algorithm(" + hmacAlgorithm.Name + ") is not supported.");
        }
    }
}