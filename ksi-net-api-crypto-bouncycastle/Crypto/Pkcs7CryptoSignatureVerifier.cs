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
using NLog;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509.Store;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Guardtime.KSI.Crypto.BouncyCastle.Crypto
{
    /// <summary>
    ///     PKCS#7 signature verifier.
    /// </summary>
    public class Pkcs7CryptoSignatureVerifier : ICryptoSignatureVerifier
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        private readonly ISet _trustAnchors = new HashSet();
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

            if (!(certificateRdnSelector is CertificateSubjectRdnSelector))
            {
                throw new ArgumentException("Expected type: " + typeof(CertificateSubjectRdnSelector), nameof(certificateRdnSelector));
            }

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

            try
            {
                CmsSignedData signedData = new CmsSignedData(new CmsProcessableByteArray(signedBytes), signatureBytes);
                SignerInformationStore signerInformationStore = signedData.GetSignerInfos();
                ICollection signerCollection = signerInformationStore.GetSigners();

                IX509Store x509Store = signedData.GetCertificates("collection");

                if (signerCollection.Count > 1)
                {
                    throw new PkiVerificationErrorException("Signature contains more than one SignerInformation element.");
                }

                IEnumerator signerInfoCollectionEnumerator = signerCollection.GetEnumerator();
                signerInfoCollectionEnumerator.MoveNext();

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

                // Verify signer information
                X509Certificate certificate = (X509Certificate)x509CertificateCollectionEnumerator.Current;
                if (!signerInfo.Verify(certificate))
                {
                    throw new PkiVerificationFailedException("Signer information does not match with certificate.");
                }

                // Verify certificate with selector
                if (!_certificateRdnSelector.IsMatch(certificate))
                {
                    throw new PkiVerificationFailedException("Certificate did not match with certificate subject rdn selector.");
                }

                ValidateCertPath(certificate, x509Store);
            }
            catch (PkiVerificationFailedException ex)
            {
                Logger.Warn(string.Format("Failed to verify PKCS#7 signature.{0}Exception: {1}{0}Trust anchors: {0}{2}", Environment.NewLine, ex, GetTrustAnchorsString()));

                throw;
            }

            catch (Exception e)
            {
                throw new PkiVerificationErrorException("Error when verifying PKCS#7 signature.", e);
            }
        }

        /// <summary>
        /// Validate certificate path.
        /// </summary>
        /// <param name="certificate">certificate</param>
        /// <param name="x509Store">x509 store</param>
        protected virtual void ValidateCertPath(X509Certificate certificate, IX509Store x509Store)
        {
            // Cert path checker
            PkixCertPathChecker certPathChecker = new CertPathChecker();

            // Validate certificate path
            X509CertStoreSelector x509CertStoreSelector = new X509CertStoreSelector { Certificate = certificate };

            // Build cert path
            PkixBuilderParameters pkixBuilderParameters = new PkixBuilderParameters(_trustAnchors, x509CertStoreSelector);
            pkixBuilderParameters.AddStore(x509Store);
            pkixBuilderParameters.AddCertPathChecker(certPathChecker);
            pkixBuilderParameters.IsRevocationEnabled = false;

            PkixCertPath pkixCertPath;

            try
            {
                PkixCertPathBuilderResult pkixCertPathBuilderResult = new PkixCertPathBuilder().Build(pkixBuilderParameters);
                pkixCertPath = pkixCertPathBuilderResult.CertPath;
            }
            catch (PkixCertPathBuilderException e)
            {
                throw new PkiVerificationFailedException("Could not build certificate path.", e);
            }

            // Create pkix parameteres
            PkixParameters pkixParameters = new PkixParameters(_trustAnchors);
            pkixParameters.AddCertPathChecker(certPathChecker);
            pkixParameters.IsRevocationEnabled = false;

            try
            {
                // Validate path
                new PkixCertPathValidator().Validate(pkixCertPath, pkixParameters);
            }
            catch (PkixCertPathValidatorException e)
            {
                throw new PkiVerificationFailedException("Failed to verify PKCS#7 signature.", e);
            }
        }

        private string GetTrustAnchorsString()
        {
            StringBuilder sb = new StringBuilder();
            foreach (object c in _trustAnchors)
            {
                sb.AppendLine("------------------ Trust anchor --------------------");
                sb.AppendLine(c.ToString());
            }

            return sb.ToString();
        }

        /// <summary>
        /// Certificate path checker.
        /// </summary>
        private class CertPathChecker : PkixCertPathChecker
        {
            public override void Init(bool forward)
            {
            }

            public override bool IsForwardCheckingSupported()
            {
                return true;
            }

            public override ISet GetSupportedExtensions()
            {
                return null;
            }

            public override void Check(X509Certificate cert, ISet unresolvedCritExts)
            {
                if (unresolvedCritExts.IsEmpty)
                {
                    return;
                }

                // TODO: is this correct behavior?
                unresolvedCritExts.Remove(Org.BouncyCastle.Asn1.X509.X509Extensions.ExtendedKeyUsage.Id);
            }
        }
    }
}