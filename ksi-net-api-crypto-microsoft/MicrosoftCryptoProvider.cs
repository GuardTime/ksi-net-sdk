using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI
{
    /// <summary>
    /// Crypto provider.
    /// </summary>
    public class MicrosoftCryptoProvider : ICryptoProvider
    {
        /// <summary>
        /// Get data hasher.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public IDataHasher GetDataHasher(HashAlgorithm algorithm)
        {
            return new DataHasher(algorithm);
        }

        /// <summary>
        /// Get PKCS#7 crypto signature verifier.
        /// </summary>
        /// <returns>PKCS#7 verifier</returns>
        public ICryptoSignatureVerifier GetPkcs7CryptoSignatureVerifier(X509Store trustStore, ICertificateSubjectRdnSelector certificateRdnSelector)
        {
            return new Pkcs7CryptoSignatureVerifier(trustStore, certificateRdnSelector);
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

        /// <summary>
        /// Get HMAC hasher.
        /// </summary>
        /// <returns></returns>
        public IHmacHasher GetHmacHasher()
        {
            return new HmacHasher();
        }
    }
}