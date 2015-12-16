using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI
{
    /// <summary>
    /// Crypto provider.
    /// </summary>
    public interface ICryptoProvider
    {
        /// <summary>
        /// Get data hasher.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        IDataHasher GetDataHasher(HashAlgorithm algorithm);

        /// <summary>
        /// Get PKCS#7 crypto signature verifier.
        /// </summary>
        /// <returns>PKCS#7 verifier</returns>
        ICryptoSignatureVerifier GetPkcs7CryptoSignatureVerifier(X509Certificate2Collection trustAnchors, ICertificateSubjectRdnSelector certificateRdnSelector);

        /// <summary>
        /// Get RSA signature verifier.
        /// </summary>
        /// <param name="algorithm">hash algorithm</param>
        /// <returns>RSA signature verifier</returns>
        ICryptoSignatureVerifier GetRsaCryptoSignatureVerifier(string algorithm);

        /// <summary>
        /// Get HMAC hasher.
        /// </summary>
        /// <returns></returns>
        IHmacHasher GetHmacHasher();
    }
}