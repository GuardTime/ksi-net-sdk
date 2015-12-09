namespace Guardtime.KSI.Crypto
{
    public class CryptoSignatureVerificationData
    {
        public byte[] CertificateBytes { get; set; }

        public CryptoSignatureVerificationData(byte[] certificate)
        {
            // TODO: Check null?
            CertificateBytes = certificate;
        }
    }
}