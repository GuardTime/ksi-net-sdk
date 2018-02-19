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

using System;
using Guardtime.KSI.Exceptions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Guardtime.KSI.Crypto.BouncyCastle.Crypto
{
    /// <summary>
    ///     RSA signature verifier.
    /// </summary>
    public class RsaCryptoSignatureVerifier : ICryptoSignatureVerifier
    {
        private readonly string _algorithm;

        /// <summary>
        /// Create RSA crypto signature verifier instance.
        /// </summary>
        /// <param name="algorithm">digest algorithm</param>
        public RsaCryptoSignatureVerifier(string algorithm)
        {
            if (algorithm == null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            _algorithm = algorithm;
        }

        /// <summary>
        ///     Verify signed bytes and signature.
        /// </summary>
        /// <param name="signedBytes">signed bytes</param>
        /// <param name="signatureBytes">signature bytes</param>
        /// <param name="data">must include certificate bytes</param>
        public void Verify(byte[] signedBytes, byte[] signatureBytes, CryptoSignatureVerificationData data)
        {
            if (signedBytes == null)
            {
                throw new ArgumentNullException(nameof(signedBytes));
            }

            if (signatureBytes == null)
            {
                throw new ArgumentNullException(nameof(signatureBytes));
            }

            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            byte[] certificateBytes = data.CertificateBytes;

            if (certificateBytes == null)
            {
                throw new PkiVerificationErrorException("Certificate in data parameter cannot be null.");
            }

            X509Certificate certificate;

            try
            {
                certificate = new X509CertificateParser().ReadCertificate(certificateBytes);
            }
            catch (Exception e)
            {
                throw new PkiVerificationErrorException("Could not create certificate from given bytes.", e);
            }

            if (certificate == null)
            {
                throw new PkiVerificationErrorException("Could not create certificate from given bytes.");
            }

            CertificateTimeVerifier.Verify(certificate, data.SignTime);

            try
            {
                ISigner signer = SignerUtilities.GetSigner(_algorithm + "withRSA");
                signer.Init(false, certificate.GetPublicKey());
                signer.BlockUpdate(signedBytes, 0, signedBytes.Length);

                if (!signer.VerifySignature(signatureBytes))
                {
                    throw new PkiVerificationFailedException("Failed to verify RSA signature.");
                }
            }
            catch (PkiVerificationFailedException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PkiVerificationErrorException("Error when verifying RSA signature.", e);
            }
        }
    }
}