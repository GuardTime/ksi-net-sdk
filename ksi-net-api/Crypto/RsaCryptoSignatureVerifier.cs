using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Crypto
{
    /// <summary>
    /// RSA signature verifier.
    /// </summary>
    public class RsaCryptoSignatureVerifier : ICryptoSignatureVerifier
    {
        /// <see cref="ICryptoSignatureVerifier"/>
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
                throw new KsiException("Invalid certificate: null");
            }

            if (digestAlgorithm == null)
            {
                throw new KsiException("Invalid digest algorithm: null");
            }

            if (certificate.PublicKey == null)
            {
                throw new KsiException("No public key in certificate");
            }

            // TODO: Throw ksi exception
            using (RSACryptoServiceProvider serviceProvider = (RSACryptoServiceProvider)certificate.PublicKey.Key)
            {
                serviceProvider.VerifyData(signedBytes, data["digestAlgorithm"], signatureBytes);
            }
        }
    }
}