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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Guardtime.KSI.Crypto.BouncyCastle.Hashing
{
    /// <summary>
    /// Digest provider
    /// </summary>
    public static class DigestProvider
    {
        /// <summary>
        /// Returns digest
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static IDigest GetDigest(HashAlgorithm algorithm)
        {
            if (algorithm == HashAlgorithm.Sha1)
            {
                return new Sha1Digest();
            }
            if (algorithm == HashAlgorithm.Sha2256)
            {
                return new Sha256Digest();
            }
            if (algorithm == HashAlgorithm.Ripemd160)
            {
                return new RipeMD160Digest();
            }
            if (algorithm == HashAlgorithm.Sha2384)
            {
                return new Sha384Digest();
            }
            if (algorithm == HashAlgorithm.Sha2512)
            {
                return new Sha512Digest();
            }
            throw new HashingException("Hash algorithm(" + algorithm.Name + ") is not supported.");
        }
    }
}