using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Crypto
{
    /// <summary>
    ///     RSA signature verifier.
    /// </summary>
    public class RsaCryptoSignatureVerifier : ICryptoSignatureVerifier
    {
        /// <see cref="ICryptoSignatureVerifier" />
        /// <param name="signedBytes">signed bytes</param>
        /// <param name="signatureBytes">signature bytes</param>
        /// <param name="data">must consist of 2 parameters, "certificate" => X509Certificate2, "digestAlgorithm" => string</param>
        /// <exception cref="PkiVerificationException">thrown when verification process cannot complete</exception>
        public void Verify(byte[] signedBytes, byte[] signatureBytes, CryptoSignatureVerificationData data)
        {
            X509Certificate2 certificate = null;
            object digestAlgorithm = null;
            if (data != null)
            {
                certificate = data.Certificate;
                digestAlgorithm = data.DigestAlgorithm;
            }

            if (certificate == null)
            {
                throw new PkiVerificationException("Certificate in data parameter cannot be null.");
            }

            if (digestAlgorithm == null)
            {
                throw new PkiVerificationException("Digest algorithm in data parameter cannot be null.");
            }

            if (certificate.PublicKey == null)
            {
                throw new PkiVerificationException("No public key in certificate.");
            }

            using (RSACryptoServiceProvider serviceProvider = (RSACryptoServiceProvider)certificate.PublicKey.Key)
            {
                if (!serviceProvider.VerifyData(signedBytes, digestAlgorithm, signatureBytes))
                {
                    throw new PkiVerificationException("Failed to verify RSA signature.");
                }
            }
        }
    }
}