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

using System;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;

namespace Guardtime.KSI.Trust
{
    /// <summary>
    ///     PKI trust store provider. Used for verifying x509 signatures.
    /// </summary>
    public class PkiTrustStoreProvider : IPkiTrustProvider
    {
        private readonly X509Store _trustStore;
        private readonly ICertificateSubjectRdnSelector _certificateRdnSelector;

        /// <summary>
        /// Create PKI trust store provider instance.
        /// </summary>
        /// <param name="trustStore">Trust anchors</param>
        /// <param name="certificateRdnSelector">Certificate subject RDN selector for verifying certificate subject.</param>
        public PkiTrustStoreProvider(X509Store trustStore, ICertificateSubjectRdnSelector certificateRdnSelector)
        {
            if (trustStore == null)
            {
                throw new ArgumentNullException(nameof(trustStore));
            }

            if (certificateRdnSelector == null)
            {
                throw new ArgumentNullException(nameof(certificateRdnSelector));
            }

            _trustStore = trustStore;
            _certificateRdnSelector = certificateRdnSelector;
        }

        /// <summary>
        ///     Verify bytes with x509 signature.
        /// </summary>
        /// <param name="signedBytes">Bytes to be verified</param>
        /// <param name="signatureBytes">Byte array containing signature</param>
        public void Verify(byte[] signedBytes, byte[] signatureBytes)
        {
            if (signedBytes == null)
            {
                throw new ArgumentNullException(nameof(signedBytes));
            }

            if (signatureBytes == null)
            {
                throw new ArgumentNullException(nameof(signatureBytes));
            }

            ICryptoSignatureVerifier verifier = KsiProvider.CreatePkcs7CryptoSignatureVerifier(_trustStore, _certificateRdnSelector);
            verifier.Verify(signedBytes, signatureBytes, null);
        }
    }
}