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
        /// <exception cref="CryptoVerificationException">thrown when verification process cannot complete</exception>
        public void Verify(byte[] signedBytes, byte[] signatureBytes, Dictionary<string, object> data)
        {
            X509Certificate2 certificate = null;
            object digestAlgorithm = null;
            if (data != null)
            {
                if (data.ContainsKey("certificate"))
                {
                    certificate = data["certificate"] as X509Certificate2;
                }

                if (data.ContainsKey("digestAlgorithm"))
                {
                    digestAlgorithm = data["digestAlgorithm"];
                }
            }

            if (certificate == null)
            {
                throw new CryptoVerificationException("Invalid certificate in data: null");
            }

            if (digestAlgorithm == null)
            {
                throw new CryptoVerificationException("Invalid digest algorithm in data: null");
            }

            if (certificate.PublicKey == null)
            {
                throw new CryptoVerificationException("No public key in certificate");
            }

            using (RSACryptoServiceProvider serviceProvider = (RSACryptoServiceProvider) certificate.PublicKey.Key)
            {
                if (!serviceProvider.VerifyData(signedBytes, data["digestAlgorithm"], signatureBytes))
                {
                    throw new CryptoVerificationException("Failed to verify RSA signature");
                }
            }
        }
    }
}