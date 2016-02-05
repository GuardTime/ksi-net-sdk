using System;
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

        /// <summary>
        ///     Verify signed bytes and signature.
        /// </summary>
        /// <param name="signedBytes">signed bytes</param>
        /// <param name="signatureBytes">signature bytes</param>
        /// <param name="data">must include certificate bytes</param>
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

            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            byte[] certificateBytes = data.CertificateBytes;

            if (certificateBytes == null)
            {
                throw new PkiVerificationErrorException("Certificate in data parameter cannot be null.");
            }

            try
            {
                X509Certificate2 certificate = new X509Certificate2(certificateBytes);

                using (RSACryptoServiceProvider serviceProvider = (RSACryptoServiceProvider)certificate.PublicKey.Key)
                {
                    if (!serviceProvider.VerifyData(signedBytes, _algorithm, signatureBytes))
                    {
                        throw new PkiVerificationFailedException("Failed to verify RSA signature.");
                    }
                }
            }
            catch (PkiVerificationFailedException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PkiVerificationErrorException("Error when verifying RSA signature.", e);
            }
        }
    }
}