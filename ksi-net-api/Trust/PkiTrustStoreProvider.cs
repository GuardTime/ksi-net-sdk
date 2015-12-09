using System;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Trust
{
    /// <summary>
    ///     PKI trust store provider.
    /// </summary>
    public class PkiTrustStoreProvider : IPkiTrustProvider
    {
        private readonly X509Certificate2Collection _trustAnchors;
        private readonly ICertificateRdnSubjectSelector _certificateRdnSelector;

        public PkiTrustStoreProvider(X509Certificate2Collection trustAnchors, ICertificateRdnSubjectSelector certificateRdnSelector)
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
        ///     Verify bytes with x509 signature.
        /// </summary>
        /// <param name="signedBytes"></param>
        /// <param name="signatureBytes"></param>
        public void Verify(byte[] signedBytes, byte[] signatureBytes)
        {
            // TODO: Check for better exception
            if (signedBytes == null)
            {
                throw new PkiVerificationErrorException("Invalid signed bytes: null.");
            }

            if (signatureBytes == null)
            {
                throw new PkiVerificationErrorException("Invalid signature bytes: null.");
            }

            ICryptoSignatureVerifier verifier = KsiProvider.GetPkcs7CryptoSignatureVerifier(_trustAnchors, _certificateRdnSelector);
            verifier.Verify(signedBytes, signatureBytes, null);

            // TODO: Verify email also
            //Console.WriteLine(signedCms.SignerInfos[0].Certificate.GetNameInfo(X509NameType.EmailName, false));
        }
    }
}