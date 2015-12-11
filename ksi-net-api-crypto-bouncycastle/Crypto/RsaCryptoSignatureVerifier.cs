using System;
using Guardtime.KSI.Exceptions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

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
                X509Certificate certificate = new X509CertificateParser().ReadCertificate(certificateBytes);

                ISigner signer = SignerUtilities.GetSigner(_algorithm + "withRSA");
                signer.Init(false, certificate.GetPublicKey());
                signer.BlockUpdate(signedBytes, 0, signedBytes.Length);

                if (!signer.VerifySignature(signatureBytes))
                {
                    throw new PkiVerificationFailedException("Failed to verify RSA signature.");
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