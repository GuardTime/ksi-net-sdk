using System;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Guardtime.KSI.Crypto
{
    /// <summary>
    ///     PKCS#7 signature verifier.
    /// </summary>
    public class Pkcs7CryptoSignatureVerifier : ICryptoSignatureVerifier
    {
        private readonly X509Certificate2Collection _trustAnchors;

        public Pkcs7CryptoSignatureVerifier(X509Certificate2Collection trustAnchors, ICertificateRdnSubjectSelector certificateRdnSelector)
        {
            if (trustAnchors == null)
            {
                throw new ArgumentNullException(nameof(trustAnchors));
            }

            _trustAnchors = trustAnchors;
        }

        /// <summary>
        ///     Verify signed bytes and PKCS#7 signature.
        /// </summary>
        /// <param name="signedBytes">signed bytes</param>
        /// <param name="signatureBytes">signature bytes</param>
        /// <param name="data">other data</param>
        public void Verify(byte[] signedBytes, byte[] signatureBytes, CryptoSignatureVerificationData data)
        {
            // TODO: Check bytes
            try
            {
                SignedCms signedCms = new SignedCms(new ContentInfo(signedBytes), true);
                signedCms.Decode(signatureBytes);
                signedCms.CheckSignature(_trustAnchors, false);
            }
            catch (Exception e)
            {
                throw new Exception("Failed to verify PKCS#7 signature.", e);
            }
        }
    }
}