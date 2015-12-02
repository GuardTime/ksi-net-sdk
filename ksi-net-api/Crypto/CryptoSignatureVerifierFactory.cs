using System;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Crypto
{
    /// <summary>
    ///     Crypto signature verifier factory.
    /// </summary>
    public static class CryptoSignatureVerifierFactory
    {
        /// <summary>
        ///     Get crypto signature verifier by oid.
        /// </summary>
        /// <param name="oid">signature oid</param>
        /// <param name="trustAnchors">trust anchor collection</param>
        /// <param name="certificateRdnSelector"></param>
        /// <returns>signature verifier</returns>
        /// <exception cref="InvalidOperationException">thrown when signature oid is not supported</exception>
        public static ICryptoSignatureVerifier GetCryptoSignatureVerifierByOid(string oid, X509Certificate2Collection trustAnchors, ICertificateRdnSubjectSelector certificateRdnSelector)
        {
            switch (oid)
            {
                case "1.2.840.113549.1.1.11":
                    return GetRsaCryptoSignatureVerifier("SHA256");
                case "1.2.840.113549.1.7.2":
                    return GetPkcs7CryptoSignatureVerifier(trustAnchors, certificateRdnSelector);
                default:
                    throw new PkiVerificationException("Cryptographic signature not supported.");
            }
        }

        /// <summary>
        /// Get PKCS#7 crypto signature verifier.
        /// </summary>
        /// <returns>PKCS#7 verifier</returns>
        public static Pkcs7CryptoSignatureVerifier GetPkcs7CryptoSignatureVerifier(X509Certificate2Collection trustAnchors, ICertificateRdnSubjectSelector certificateRdnSelector)
        {
            return new Pkcs7CryptoSignatureVerifier(trustAnchors, certificateRdnSelector);
        }

        /// <summary>
        /// Get RSA signature verifier.
        /// </summary>
        /// <param name="algorithm">hash algorithm</param>
        /// <returns>RSA signature verifier</returns>
        public static RsaCryptoSignatureVerifier GetRsaCryptoSignatureVerifier(string algorithm)
        {
            return new RsaCryptoSignatureVerifier(algorithm);
        }
    }
}