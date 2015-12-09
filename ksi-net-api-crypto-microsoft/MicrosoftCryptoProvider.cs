using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI
{
    public class MicrosoftCryptoProvider : ICryptoProvider
    {
        public IDataHasher GetDataHasher(HashAlgorithm algorithm)
        {
            return new DataHasher(algorithm);
        }

        /// <summary>
        /// Get PKCS#7 crypto signature verifier.
        /// </summary>
        /// <returns>PKCS#7 verifier</returns>
        public ICryptoSignatureVerifier GetPkcs7CryptoSignatureVerifier(X509Certificate2Collection trustAnchors, ICertificateRdnSubjectSelector certificateRdnSelector)
        {
            return new Pkcs7CryptoSignatureVerifier(trustAnchors, certificateRdnSelector);
        }

        /// <summary>
        /// Get RSA signature verifier.
        /// </summary>
        /// <param name="algorithm">hash algorithm</param>
        /// <returns>RSA signature verifier</returns>
        public ICryptoSignatureVerifier GetRsaCryptoSignatureVerifier(string algorithm)
        {
            return new RsaCryptoSignatureVerifier(algorithm);
        }

        public IHmacHasher GetHmacHasher()
        {
            return new HmacHasher();
        }
    }
}