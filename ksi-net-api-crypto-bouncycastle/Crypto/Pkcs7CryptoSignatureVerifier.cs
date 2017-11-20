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
using System.Collections;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Guardtime.KSI.Exceptions;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509.Store;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Guardtime.KSI.Crypto.BouncyCastle.Crypto
{
    /// <summary>
    ///     PKCS#7 signature verifier. Used to verify certificate against trust anchors and verify that certificate subject contains specified RDN.
    /// </summary>
    public class Pkcs7CryptoSignatureVerifier : ICryptoSignatureVerifier
    {
        private readonly ISet _trustAnchors;
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
            if (trustAnchors == null || trustAnchors.Count == 0)
            {
                throw new ArgumentException("Non-empty collection required. Parameter: " + trustAnchors);
            }

            if (certificateRdnSelector == null)
            {
                throw new ArgumentNullException(nameof(certificateRdnSelector));
            }

            _trustAnchors = new HashSet();

            foreach (X509Certificate2 certificate in trustAnchors)
            {
                _trustAnchors.Add(new TrustAnchor(DotNetUtilities.FromX509Certificate(certificate), null));
            }

            _certificateRdnSelector = certificateRdnSelector;
        }

        /// <summary>
        ///     Verify signed bytes and PKCS#7 signature.
        /// </summary>
        /// <param name="signedBytes">signed bytes</param>
        /// <param name="signatureBytes">signature bytes</param>
        /// <param name="data">other data</param>
        public void Verify(byte[] signedBytes, byte[] signatureBytes, CryptoSignatureVerificationData data = null)
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

            CmsSignedData signedData;

            try
            {
                CmsProcessableByteArray cmsProcessableByteArray = new CmsProcessableByteArray(signedBytes);
                signedData = new CmsSignedData(cmsProcessableByteArray, signatureBytes);
            }
            catch (Exception e)
            {
                throw new PkiVerificationErrorException("Cannot create signature from " + nameof(signatureBytes), e);
            }

            SignerInformationStore signerInformationStore = signedData.GetSignerInfos();
            ICollection signerCollection = signerInformationStore.GetSigners();

            if (signerCollection.Count == 0)
            {
                throw new PkiVerificationFailedException("Signature does not contain any SignerInformation element.");
            }

            IX509Store x509Store = signedData.GetCertificates("collection");

            IEnumerator signerInfoCollectionEnumerator = signerCollection.GetEnumerator();
            while (signerInfoCollectionEnumerator.MoveNext())
            {
                SignerInformation signerInfo = (SignerInformation)signerInfoCollectionEnumerator.Current;

                if (signerInfo == null)
                {
                    throw new PkiVerificationErrorException("Signature does not contain any SignerInformation element.");
                }

                ICollection x509Collection = x509Store.GetMatches(signerInfo.SignerID);
                IEnumerator x509CertificateCollectionEnumerator = x509Collection.GetEnumerator();
                if (!x509CertificateCollectionEnumerator.MoveNext())
                {
                    throw new PkiVerificationErrorException("Signature does not contain any x509 certificates.");
                }

                X509Certificate certificate = (X509Certificate)x509CertificateCollectionEnumerator.Current;

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
                }

                try
                {
                    if (!signerInfo.Verify(certificate))
                    {
                        throw new PkiVerificationFailedException("Signer information does not match with certificate.");
                    }
                }
                catch (CmsException e)
                {
                    throw new PkiVerificationFailedException("Failed to verify PKCS#7 signature.", e);
                }
                catch (Exception e)
                {
                    throw new PkiVerificationErrorException("Error when verifying PKCS#7 signature.", e);
                }

                ISet trustAnchors;

                if (data?.CertificateBytes != null)
                {
                    try
                    {
                        trustAnchors = new HashSet
                        {
                            new TrustAnchor(DotNetUtilities.FromX509Certificate(new X509Certificate2(data.CertificateBytes)), null)
                        };
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
                    ValidateCertPath(certificate, x509Store, trustAnchors);
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
        }

        private static void ValidateCertPath(X509Certificate certificate, IX509Store x509Store, ISet trustAnchors)
        {
            X509CertStoreSelector x509CertStoreSelector = new X509CertStoreSelector { Certificate = certificate };

            // Build cert path
            PkixBuilderParameters pkixBuilderParameters = new PkixBuilderParameters(trustAnchors, x509CertStoreSelector);
            pkixBuilderParameters.AddStore(x509Store);
            pkixBuilderParameters.IsRevocationEnabled = false;

            PkixCertPath pkixCertPath;

            try
            {
                PkixCertPathBuilderResult pkixCertPathBuilderResult = new PkixCertPathBuilder().Build(pkixBuilderParameters);
                pkixCertPath = pkixCertPathBuilderResult.CertPath;
            }
            catch (PkixCertPathBuilderException e)
            {
                throw new PkiVerificationFailedException("Could not build certificate path.", e, GetTrustAnchorsString(trustAnchors));
            }

            PkixParameters pkixParameters = new PkixParameters(trustAnchors) { IsRevocationEnabled = false };

            try
            {
                // Validate path
                new PkixCertPathValidator().Validate(pkixCertPath, pkixParameters);
            }
            catch (PkixCertPathValidatorException e)
            {
                throw new PkiVerificationFailedException("Failed to verify PKCS#7 signature.", e, GetTrustAnchorsString(trustAnchors));
            }
        }

        private static string GetTrustAnchorsString(ISet trustAnchors)
        {
            StringBuilder sb = new StringBuilder();
            foreach (object c in trustAnchors)
            {
                sb.AppendLine("------------------ Trust anchor --------------------");
                sb.AppendLine(c.ToString());
            }

            return sb.ToString();
        }
    }
}