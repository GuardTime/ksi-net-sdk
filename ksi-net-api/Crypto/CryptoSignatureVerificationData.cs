using System.Security.Cryptography.X509Certificates;

namespace Guardtime.KSI.Crypto
{
    public class CryptoSignatureVerificationData
    {
        public X509Certificate2 Certificate { get; set; }

        public CryptoSignatureVerificationData(X509Certificate2 certificate)
        {
            Certificate = certificate;
        }
    }
}