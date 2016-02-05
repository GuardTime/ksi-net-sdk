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
        private readonly X509Store _trustStore;
        private readonly ICertificateSubjectRdnSelector _certificateRdnSelector;

        /// <summary>
        /// Create PKI trust store provider instance.
        /// </summary>
        /// <param name="trustStore">trust anchors</param>
        /// <param name="certificateRdnSelector">certificate subject rdn selector</param>
        public PkiTrustStoreProvider(X509Store trustStore, ICertificateSubjectRdnSelector certificateRdnSelector)
        {
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
        /// <param name="signedBytes"></param>
        /// <param name="signatureBytes"></param>
        public void Verify(byte[] signedBytes, byte[] signatureBytes)
        {
            if (signedBytes == null)
            {
                throw new PkiVerificationErrorException("Invalid signed bytes: null.");
            }

            if (signatureBytes == null)
            {
                throw new PkiVerificationErrorException("Invalid signature bytes: null.");
            }

            ICryptoSignatureVerifier verifier = KsiProvider.GetPkcs7CryptoSignatureVerifier(_trustStore, _certificateRdnSelector);
            verifier.Verify(signedBytes, signatureBytes, null);
        }
    }
}