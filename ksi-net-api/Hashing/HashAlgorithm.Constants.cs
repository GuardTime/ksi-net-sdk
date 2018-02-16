/*
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

namespace Guardtime.KSI.Hashing
{
    partial class HashAlgorithm
    {
        /// <summary>
        /// Default Hash Algorithm
        /// </summary>
        public static HashAlgorithm Default => Sha2256;

        /// <summary>
        ///     SHA1 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha1 = new HashAlgorithm("SHA1", 0x0, 20, AlgorithmStatus.NotTrusted, null, 1467331200); // 1467331200 = 2016-07-01

        /// <summary>
        ///     SHA2-256 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha2256 = new HashAlgorithm("SHA-256", 0x01, 32, AlgorithmStatus.Normal, new string[] { "SHA2-256", "SHA2" });

        /// <summary>
        ///     RIPEMD-160 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Ripemd160 = new HashAlgorithm("RIPEMD160", 0x02, 20, AlgorithmStatus.Normal);

        /// <summary>
        ///     SHA2-384 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha2384 = new HashAlgorithm("SHA-384", 0x04, 48, AlgorithmStatus.Normal, new string[] { "SHA2-384" });

        /// <summary>
        ///     SHA2-512 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha2512 = new HashAlgorithm("SHA-512", 0x05, 64, AlgorithmStatus.Normal, new string[] { "SHA2-512" });

        /// <summary>
        ///     SHA3-224 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha3224 = new HashAlgorithm("SHA3-224", 0x07, 28, AlgorithmStatus.NotImplemented);

        /// <summary>
        ///     SHA3-256 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha3256 = new HashAlgorithm("SHA3-256", 0x08, 32, AlgorithmStatus.NotImplemented);

        /// <summary>
        ///     SHA3-384 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha3384 = new HashAlgorithm("SHA3-384", 0x09, 48, AlgorithmStatus.NotImplemented);

        /// <summary>
        ///     SHA3-512 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha3512 = new HashAlgorithm("SHA3-512", 0x0A, 64, AlgorithmStatus.NotImplemented);

        /// <summary>
        ///     SM3 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sm3 = new HashAlgorithm("SM3", 0x0B, 32, AlgorithmStatus.NotImplemented);
    }
}