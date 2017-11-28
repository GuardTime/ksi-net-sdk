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

namespace Guardtime.KSI.Crypto.Microsoft.Crypto
{
    /// <summary>
    ///     PKCS#7 signature verifier. Used to verify certificate against trust anchors and verify that certificate subject contains specified RDN.
    /// </summary>
    public class Pkcs7CryptoSignatureVerifier : ICryptoSignatureVerifier
    {
        private readonly X509Certificate2Collection _trustAnchors;
        private readonly ICertificateSubjectRdnSelector _certificateRdnSelector;

        /// <summary>
        /// Create PKCS#7 signature verifier instance.
        /// </summary>
        public Pkcs7CryptoSignatureVerifier()
        {
        }

        /// <summary>
        /// Create PKCS#7 signature verifier instance.
        /// </summary>
        /// <param name="trustAnchors">Trust anchors to verify against</param>
        /// <param name="certificateRdnSelector">Certificate subject RDN selector. Used to verify that certificate subject contains specified RDN</param>
        public Pkcs7CryptoSignatureVerifier(X509Certificate2Collection trustAnchors, ICertificateSubjectRdnSelector certificateRdnSelector)
        {
            if (trustAnchors == null)
            {
                throw new ArgumentNullException(nameof(trustAnchors));
            }

            if (certificateRdnSelector == null)
            {
                throw new ArgumentNullException(nameof(certificateRdnSelector));
            }

            if (trustAnchors.Count == 0)
            {
                throw new ArgumentException("Non empty collection is expected.", nameof(trustAnchors));
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

            if (_trustAnchors == null && data?.CertificateBytes == null)
            {
                throw new ArgumentException("No trust anchors given.");
            }

            SignedCms signedCms;

            try
            {
                signedCms = new SignedCms(new ContentInfo(signedBytes), true);
                //    signedCms = new SignedCms();
                signedCms.Decode(signatureBytes);
            }
            catch (Exception e)
            {
                throw new PkiVerificationErrorException("Error when verifying PKCS#7 signature.", e);
            }

            if (signedCms.SignerInfos.Count == 0)
            {
                throw new PkiVerificationFailedException("Signature does not contain any SignerInformation element.");
            }

            foreach (SignerInfo signerInfo in signedCms.SignerInfos)
            {
                X509Certificate2 certificate = signerInfo.Certificate;

                if (data != null)
                {
                    try
                    {
                        CertificateTimeVerifier.Verify(certificate, data.SignTime);
                    }
                    catch (PkiVerificationFailedCertNotValidException ex)
                    {
                        throw new PkiVerificationFailedCertNotValidException("PKCS#7 signature certificate is not valid.", ex);
                    }
                }

                if (_certificateRdnSelector != null)
                {
                    try
                    {
                        if (!_certificateRdnSelector.IsMatch(certificate))
                        {
                            throw new PkiVerificationFailedException("Certificate did not match with certificate subject RDN selector.");
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
                }

                X509Certificate2Collection trustAnchors;

                if (data?.CertificateBytes != null)
                {
                    try
                    {
                        trustAnchors = new X509Certificate2Collection(new X509Certificate2(data.CertificateBytes));
                    }
                    catch (Exception e)
                    {
                        throw new PkiVerificationErrorException("Cannot create trust anchor certificate from " + nameof(data.CertificateBytes), e);
                    }
                }
                else
                {
                    trustAnchors = _trustAnchors;
                }

                try
                {
                    signedCms.CheckSignature(trustAnchors, true);
                }
                catch (Exception e)
                {
                    throw new PkiVerificationFailedException("Failed to verify PKCS#7 signature.", e, GetCertInfoString(trustAnchors));
                }

                ValidateCertPath(trustAnchors, certificate, data?.SignTime == null);
            }
        }

        private static void ValidateCertPath(X509Certificate2Collection trustAnchors, X509Certificate2 certificate, bool verifyCertTimesAgainstSystemTime)
        {
            X509VerificationFlags flags = X509VerificationFlags.AllowUnknownCertificateAuthority;

            if (!verifyCertTimesAgainstSystemTime)
            {
                // do not verify certificates against local system time.
                flags |= X509VerificationFlags.IgnoreNotTimeValid;
            }

            X509Chain chain = new X509Chain { ChainPolicy = { VerificationFlags = flags } };

            bool isChainValid = chain.Build(certificate);

            if (!isChainValid)
            {
                List<string> errors = new List<string>();

                foreach (X509ChainStatus status in chain.ChainStatus)
                {
                    errors.Add(string.Format("{0} ({1})", status.StatusInformation, status.Status));
                }

                string certificateErrorsString = errors.Count == 0 ? "Unknown errors." : string.Join(", ", errors.ToArray());
                throw new PkiVerificationFailedException("Trust chain did not complete to the known authority anchor. Errors: " + certificateErrorsString);
            }

            foreach (X509ChainElement chainElement in chain.ChainElements)
            {
                foreach (X509Certificate2 cert in trustAnchors)
                {
                    if (chainElement.Certificate.Thumbprint == cert.Thumbprint)
                    {
                        return;
                    }
                }
            }

            throw new PkiVerificationFailedException("Trust chain did not complete to the known authority anchor. Thumbprints did not match.", null,
                GetCertInfoString(trustAnchors, chain.ChainElements));
        }

        private static string GetCertInfoString(X509Certificate2Collection trustAnchors, X509ChainElementCollection chainElements = null)
        {
            StringBuilder sb = new StringBuilder();

            if (chainElements != null)
            {
                sb.AppendLine();
                sb.AppendLine("X509 chain elements: ");

                foreach (X509ChainElement chainElement in chainElements)
                {
                    sb.AppendLine("------------------- Chain element -------------------");
                    sb.AppendLine(chainElement.Certificate.ToString());
                }
            }

            sb.AppendLine();
            sb.AppendLine("Trust anchors: ");

            foreach (X509Certificate2 cert in trustAnchors)
            {
                sb.AppendLine("------------------ Trust anchor --------------------");
                sb.AppendLine(cert.ToString());
            }

            return sb.ToString();
        }
    }
}