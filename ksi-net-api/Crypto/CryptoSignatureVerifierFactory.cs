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
        ///     Get crypto signature verifier by oid.
        /// </summary>
        /// <param name="oid">signature oid</param>
        /// <param name="digestAlgorithm">algorithm used for given signature</param>
        /// <returns>signature verifier</returns>
        /// <exception cref="InvalidOperationException">thrown when signature oid is not supported</exception>
        public static ICryptoSignatureVerifier GetCryptoSignatureVerifierByOid(string oid)
        {
            switch (oid)
            {
                case "1.2.840.113549.1.1.11":
                    return GetRsaCryptoSignatureVerifier("SHA256");
                case "1.2.840.113549.1.7.2":
                    return GetPkcs7CryptoSignatureVerifier();
                default:
                    throw new PkiVerificationException("Cryptographic signature not supported.");
            }
        }

        public static Pkcs7CryptoSignatureVerifier GetPkcs7CryptoSignatureVerifier()
        {
            return new Pkcs7CryptoSignatureVerifier();
        }

        public static RsaCryptoSignatureVerifier GetRsaCryptoSignatureVerifier(string algorithm)
        {
            return new RsaCryptoSignatureVerifier(algorithm);
        }
    }
}