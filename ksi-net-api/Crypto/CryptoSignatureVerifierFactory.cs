using System;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Crypto
{
    /// <summary>
    ///     Crypto signature verifier factory.
    /// </summary>
    public static class CryptoSignatureVerifierFactory
    {
        /// <summary>
        ///     RSA signature verifier.
        /// </summary>
        public static readonly RsaCryptoSignatureVerifier RsaSignatureVerifier = new RsaCryptoSignatureVerifier();

        /// <summary>
        ///     PKCS#7 signature verifier.
        /// </summary>
        public static readonly Pkcs7CryptoSignatureVerifier Pkcs7SignatureVerifier = new Pkcs7CryptoSignatureVerifier();

        /// <summary>
        ///     Get crypto signature verifier by oid.
        /// </summary>
        /// <param name="oid">signature oid</param>
        /// <param name="digestAlgorithm">algorithm used for given signature</param>
        /// <returns>signature verifier</returns>
        /// <exception cref="InvalidOperationException">thrown when signature oid is not supported</exception>
        public static ICryptoSignatureVerifier GetCryptoSignatureVerifierByOid(string oid, out string digestAlgorithm)
        {
            switch (oid)
            {
                case "1.2.840.113549.1.1.11":
                    digestAlgorithm = "SHA256";
                    return RsaSignatureVerifier;
                case "1.2.840.113549.1.7.2":
                    digestAlgorithm = null;
                    return Pkcs7SignatureVerifier;
                default:
                    throw new PkiVerificationException("Cryptographic signature not supported.");
            }
        }
    }
}