using System;

namespace Guardtime.KSI.Crypto
{
    public class CryptoSignatureVerificationData
    {
        public byte[] CertificateBytes { get; set; }

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