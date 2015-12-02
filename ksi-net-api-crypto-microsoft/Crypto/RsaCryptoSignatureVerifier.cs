using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Guardtime.KSI.Crypto
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

        /// <see cref="ICryptoSignatureVerifier" />
        /// <param name="signedBytes">signed bytes</param>
        /// <param name="signatureBytes">signature bytes</param>
        /// <param name="data">must consist of 2 parameters, "certificate" => X509Certificate2, "digestAlgorithm" => string</param>
        public void Verify(byte[] signedBytes, byte[] signatureBytes, CryptoSignatureVerificationData data)
        {
            // TODO: Check bytes
            byte[] certificateBytes = null;

            if (data != null)
            {
                certificateBytes = data.CertificateBytes;
            }

            if (certificateBytes == null)
            {
                throw new Exception("Certificate in data parameter cannot be null.");
            }

            X509Certificate2 certificate = new X509Certificate2(certificateBytes);

            if (certificate.PublicKey == null)
            {
                throw new Exception("No public key in certificate.");
            }

            using (RSACryptoServiceProvider serviceProvider = (RSACryptoServiceProvider)certificate.PublicKey.Key)
            {
                if (!serviceProvider.VerifyData(signedBytes, _algorithm, signatureBytes))
                {
                    throw new Exception("Failed to verify RSA signature.");
                }
            }
        }
    }
}