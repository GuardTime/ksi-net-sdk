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
using System.Collections.Generic;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Guardtime.KSI.Exceptions;
using NLog;

namespace Guardtime.KSI.Crypto.Microsoft.Crypto
{
    /// <summary>
    ///     PKCS#7 signature verifier.
    /// </summary>
    public class Pkcs7CryptoSignatureVerifier : ICryptoSignatureVerifier
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        private readonly X509Certificate2Collection _trustAnchors;
        private readonly ICertificateSubjectRdnSelector _certificateRdnSelector;

        /// <summary>
        /// Create PKCS#7 signature verifier instance.
        /// </summary>
        /// <param name="trustAnchors">Trust anchors</param>
        /// <param name="certificateRdnSelector">Certificate subject rdn selector</param>
        public Pkcs7CryptoSignatureVerifier(X509Certificate2Collection trustAnchors, ICertificateSubjectRdnSelector certificateRdnSelector)
        {
            if (certificateRdnSelector == null)
            {
                throw new ArgumentNullException(nameof(certificateRdnSelector));
            }

            _trustAnchors = trustAnchors;
            _certificateRdnSelector = certificateRdnSelector;
        }

        /// <summary>
        ///     Verify signed bytes and PKCS#7 signature.
        /// </summary>
        /// <param name="signedBytes">signed bytes</param>
        /// <param name="signatureBytes">signature bytes</param>
        /// <param name="data">other data</param>
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

            SignedCms signedCms;

            try
            {
                signedCms = new SignedCms(new ContentInfo(signedBytes), true);
                signedCms.Decode(signatureBytes);
            }
            catch (Exception e)
            {
                throw new PkiVerificationErrorException("Error when verifying PKCS#7 signature.", e);
            }

            if (signedCms.SignerInfos.Count == 0)
            {
                throw new PkiVerificationErrorException("Signature does not contain any SignerInformation element.");
            }

            if (signedCms.SignerInfos.Count > 1)
            {
                throw new PkiVerificationErrorException("Signature contains more than one SignerInformation element.");
            }

            SignerInfo signerInfo = signedCms.SignerInfos[0];
            X509Certificate2 certificate = signerInfo.Certificate;

            try
            {
                // Verify certificate with rdn selector
                if (!_certificateRdnSelector.IsMatch(certificate))
                {
                    throw new PkiVerificationFailedException("Certificate did not match with certificate subject rdn selector.");
                }
            }
            catch (PkiVerificationFailedException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PkiVerificationErrorException("Error when verifying PKCS#7 signature.", e);
            }

            try
            {
                signedCms.CheckSignature(_trustAnchors, true);
            }
            catch (Exception e)
            {
                Logger.Warn("Failed to verify PKCS#7 signature. " + e + GetCertInfoString());

                throw new PkiVerificationFailedException("Failed to verify PKCS#7 signature.", e);
            }

            ValidateCertPath(certificate);
        }

        private void ValidateCertPath(X509Certificate2 certificate)
        {
            X509Chain chain = new X509Chain { ChainPolicy = { VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority } };

            //chain.ChainPolicy.ExtraStore.AddRange(_trustAnchors);

            bool isChainValid = chain.Build(certificate);

            if (!isChainValid)
            {
                List<string> errors = new List<string>();

                foreach (X509ChainStatus status in chain.ChainStatus)
                {
                    errors.Add(string.Format("{0} ({1})", status.StatusInformation, status.Status));
                }

                string certificateErrorsString = "Unknown errors.";

                if (errors.Count > 0)
                {
                    certificateErrorsString = string.Join(", ", errors.ToArray());
                }

                throw new PkiVerificationFailedException("Trust chain did not complete to the known authority anchor. Errors: " + certificateErrorsString);
            }

            foreach (X509ChainElement chainElement in chain.ChainElements)
            {
                foreach (X509Certificate2 cert in _trustAnchors)
                {
                    if (chainElement.Certificate.Thumbprint == cert.Thumbprint)
                    {
                        return;
                    }
                }
            }

            Logger.Warn("Failed to verify PKCS#7 signature. Trust chain did not complete to the known authority anchor. Thumbprints did not match." +
                        GetCertInfoString(chain.ChainElements));

            throw new PkiVerificationFailedException("Trust chain did not complete to the known authority anchor. Thumbprints did not match.");
        }

        private string GetCertInfoString(X509ChainElementCollection chainElements = null)
        {
            StringBuilder sb = new StringBuilder();

            if (chainElements != null)
            {
                sb.AppendLine();
                sb.AppendLine("Chain elements: ");

                foreach (X509ChainElement chainElement in chainElements)
                {
                    sb.AppendLine("------------------- Chain element -------------------");
                    sb.AppendLine(chainElement.Certificate.ToString());
                }
            }

            sb.AppendLine();
            sb.AppendLine("Trust anchors: ");

            foreach (X509Certificate2 cert in _trustAnchors)
            {
                sb.AppendLine("------------------ Trust anchor --------------------");
                sb.AppendLine(cert.ToString());
            }

            return sb.ToString();
        }
    }
}