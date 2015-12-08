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
        public static ICryptoSignatureVerifier GetCryptoSignatureVerifierByOid(string oid, X509Certificate2Collection trustAnchors,
                                                                               ICertificateRdnSubjectSelector certificateRdnSelector)
        {
            switch (oid)
            {
                case "1.2.840.113549.1.1.11":
                    return KsiProvider.GetRsaCryptoSignatureVerifier("SHA256");
                case "1.2.840.113549.1.7.2":
                    return KsiProvider.GetPkcs7CryptoSignatureVerifier(trustAnchors, certificateRdnSelector);
                default:
                    throw new PkiVerificationException("Cryptographic signature not supported.");
            }
        }
    }
}