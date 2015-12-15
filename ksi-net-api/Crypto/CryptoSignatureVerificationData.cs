using System;

namespace Guardtime.KSI.Crypto
{
    /// <summary>
    /// Crypto signature verification data
    /// </summary>
    public class CryptoSignatureVerificationData
    {
        /// <summary>
        /// Certificate bytes
        /// </summary>
        public byte[] CertificateBytes { get; set; }

        /// <summary>
        /// Create crypto signature verification data instance
        /// </summary>
        /// <param name="certificate">certificate bytes</param>
        public CryptoSignatureVerificationData(byte[] certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            CertificateBytes = certificate;
        }
    }
}