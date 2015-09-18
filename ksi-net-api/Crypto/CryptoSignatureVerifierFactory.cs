using System;
using System.Security.Cryptography;

namespace Guardtime.KSI.Crypto
{
    public static class CryptoSignatureVerifierFactory
    {
        public static readonly RsaCryptoSignatureVerifier RsaSignatureVerifier = new RsaCryptoSignatureVerifier();
        public static readonly Pkcs7CryptoSignatureVerifier Pkcs7SignatureVerifier = new Pkcs7CryptoSignatureVerifier();

        public static ICryptoSignatureVerifier GetCryptoSignatureVerificationByOid(string oid, out string digestAlgorithm)
        {
            switch (oid)
            {
                case "1.2.840.113549.1.1.11":
                    digestAlgorithm = "SHA256";
                    return RsaSignatureVerifier;
                case "1.2.840.113549.1.7.2":
                    // TODO: Not required
                    digestAlgorithm = null;
                    return Pkcs7SignatureVerifier;
                default:
                    // TODO: better exception
                    throw new InvalidOperationException("Cryptographic signature not supported");
            }
        }
    }
}