/*
 * Copyright 2013-2017 Guardtime, Inc.
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
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Crypto
{
    /// <summary>
    ///     Crypto signature verifier factory.
    /// </summary>
    public static class CryptoSignatureVerifierFactory
    {
        /// <summary>
        ///     Get crypto signature verifier by oid.
        /// </summary>
        /// <param name="oid">signature oid</param>
        /// <param name="trustStore">trust store</param>
        /// <param name="certificateRdnSelector">sertificate subject rdn selector</param>
        /// <returns>signature verifier</returns>
        public static ICryptoSignatureVerifier GetCryptoSignatureVerifierByOid(string oid, X509Store trustStore,
                                                                               ICertificateSubjectRdnSelector certificateRdnSelector)
        {
            switch (oid)
            {
                case "1.2.840.113549.1.1.11":
                    return KsiProvider.CreateRsaCryptoSignatureVerifier("SHA256");
                case "1.2.840.113549.1.7.2":
                    return KsiProvider.CreatePkcs7CryptoSignatureVerifier(trustStore, certificateRdnSelector);
                default:
                    throw new PkiVerificationErrorException("Cryptographic signature not supported. Oid: " + oid);
            }
        }
    }
}