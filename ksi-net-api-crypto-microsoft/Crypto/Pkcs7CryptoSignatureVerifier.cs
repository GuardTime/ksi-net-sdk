using System;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Crypto
{
    /// <summary>
    ///     PKCS#7 signature verifier.
    /// </summary>
    public class Pkcs7CryptoSignatureVerifier : ICryptoSignatureVerifier
    {
        private readonly X509Certificate2Collection _trustAnchors;
        private readonly ICertificateSubjectRdnSelector _certificateRdnSelector;

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
                if (!_certificateRdnSelector.Match(certificate))
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
                signedCms.CheckSignature(_trustAnchors, false);
            }
            catch (Exception e)
            {
                throw new PkiVerificationFailedException("Failed to verify PKCS#7 signature.", e);
            }
        }
    }
}