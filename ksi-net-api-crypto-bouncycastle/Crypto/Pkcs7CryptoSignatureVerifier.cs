using System;
using System.Collections;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Exceptions;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509.Store;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Guardtime.KSI.Crypto
{
    /// <summary>
    ///     PKCS#7 signature verifier.
    /// </summary>
    public class Pkcs7CryptoSignatureVerifier : ICryptoSignatureVerifier
    {
        private readonly ISet _trustAnchors = new HashSet();
        private readonly ICertificateRdnSubjectSelector _certificateRdnSelector;

        public Pkcs7CryptoSignatureVerifier(X509Certificate2Collection trustAnchors, ICertificateRdnSubjectSelector certificateRdnSelector)
        {
            if (trustAnchors == null)
            {
                throw new ArgumentNullException(nameof(trustAnchors));
            }

            if (certificateRdnSelector == null)
            {
                throw new ArgumentNullException(nameof(certificateRdnSelector));
            }

            _certificateRdnSelector = certificateRdnSelector;

            foreach (X509Certificate2 certificate in trustAnchors)
            {
                _trustAnchors.Add(new TrustAnchor(DotNetUtilities.FromX509Certificate(certificate), null));
            }
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
                if (!_certificateRdnSelector.Match(certificate))
                {
                    throw new PkiVerificationFailedException("Certificate did not match with certificate selector.");
                }

                ValidateCertPath(certificate, x509Store);
            }
            catch (PkiVerificationFailedException)
            {
                throw;
            }
            catch (PkiVerificationErrorException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PkiVerificationErrorException("Error when verifying PKCS#7 signature.", e);
            }
        }

        protected virtual void ValidateCertPath(X509Certificate certificate, IX509Store x509Store)
        {
            // Cert path checker
            CertPathChecker certPathChecker = new CertPathChecker();

            // Validate certificate path
            X509CertStoreSelector x509CertStoreSelector = new X509CertStoreSelector {Certificate = certificate};

            // Build cert path
            PkixBuilderParameters pkixBuilderParameters = new PkixBuilderParameters(_trustAnchors, x509CertStoreSelector);
            pkixBuilderParameters.AddStore(x509Store);
            pkixBuilderParameters.AddCertPathChecker(certPathChecker);
            pkixBuilderParameters.IsRevocationEnabled = false;

            PkixCertPathBuilderResult pkixCertPathBuilderResult = new PkixCertPathBuilder().Build(pkixBuilderParameters);
            PkixCertPath pkixCertPath = pkixCertPathBuilderResult.CertPath;

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
                // TODO: 
                if (unresolvedCritExts.IsEmpty)
                {
                    return;
                }

                unresolvedCritExts.Remove("2.5.29.37");
            }
        }
    }
}