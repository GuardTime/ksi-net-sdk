/*
 * Copyright 2013-2016 Guardtime, Inc.
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
using Guardtime.KSI.Hashing;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Guardtime.KSI.Crypto.BouncyCastle.Hashing
{
    /// <summary>
    /// HMAC hasher
    /// </summary>
    public class HmacHasher : IHmacHasher
    {
        /// <summary>
        ///     Calculate HMAC for data with given key.
        /// </summary>
        /// <param name="hmacAlgorithm">HMAC algorithm</param>
        /// <param name="key">HMAC key</param>
        /// <param name="data">HMAC calculation data</param>
        /// <returns>HMAC data hash</returns>
        public DataHash GetHash(HashAlgorithm hmacAlgorithm, byte[] key, byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            HMac hMac = new HMac(DigestProvider.GetDigest(hmacAlgorithm));

            hMac.Init(new KeyParameter(key));
            hMac.BlockUpdate(data, 0, data.Length);

            byte[] value = new byte[hmacAlgorithm.Length];
            hMac.DoFinal(value, 0);
            return new DataHash(hmacAlgorithm, value);
        }
    }
}