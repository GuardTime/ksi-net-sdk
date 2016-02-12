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

using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI
{
    /// <summary>
    /// Crypto provider.
    /// </summary>
    public class MicrosoftCryptoProvider : ICryptoProvider
    {
        /// <summary>
        /// Get data hasher.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public IDataHasher GetDataHasher(HashAlgorithm algorithm)
        {
            return new DataHasher(algorithm);
        }

        /// <summary>
        /// Get PKCS#7 crypto signature verifier.
        /// </summary>
        /// <returns>PKCS#7 verifier</returns>
        public ICryptoSignatureVerifier GetPkcs7CryptoSignatureVerifier(X509Store trustStore, ICertificateSubjectRdnSelector certificateRdnSelector)
        {
            return new Pkcs7CryptoSignatureVerifier(trustStore, certificateRdnSelector);
        }

        /// <summary>
        /// Get RSA signature verifier.
        /// </summary>
        /// <param name="algorithm">hash algorithm</param>
        /// <returns>RSA signature verifier</returns>
        public ICryptoSignatureVerifier GetRsaCryptoSignatureVerifier(string algorithm)
        {
            return new RsaCryptoSignatureVerifier(algorithm);
        }

        /// <summary>
        /// Get HMAC hasher.
        /// </summary>
        /// <returns></returns>
        public IHmacHasher GetHmacHasher()
        {
            return new HmacHasher();
        }
    }
}