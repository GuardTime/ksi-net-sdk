using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI
{
    public class KsiProvider
    {
        static ICryptoProvider _provider;

        public static void SetCryptoProvider(ICryptoProvider provider)
        {
            _provider = provider;
        }

        /// <summary>
        /// Get PKCS#7 crypto signature verifier.
        /// </summary>
        /// <returns>PKCS#7 verifier</returns>
        public static ICryptoSignatureVerifier GetPkcs7CryptoSignatureVerifier(X509Certificate2Collection trustAnchors, ICertificateRdnSubjectSelector certificateRdnSelector)
        {
            return _provider.GetPkcs7CryptoSignatureVerifier(trustAnchors, certificateRdnSelector);
        }

        /// <summary>
        /// Get RSA signature verifier.
        /// </summary>
        /// <param name="algorithm">hash algorithm</param>
        /// <returns>RSA signature verifier</returns>
        public static ICryptoSignatureVerifier GetRsaCryptoSignatureVerifier(string algorithm)
        {
            return _provider.GetRsaCryptoSignatureVerifier(algorithm);
        }

        public static IHmacHasher GetHmacHasher()
        {
            return _provider.GetHmacHasher();
        }

        public static IDataHasher GetDataHasher(HashAlgorithm algorithm)
        {
            return _provider.GetDataHasher(algorithm);
        }
    }
}