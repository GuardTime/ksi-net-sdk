using System;
using System.Collections.Generic;
using System.Security.Cryptography.Pkcs;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Crypto
{
    /// <summary>
    ///     PKCS#7 signature verifier.
    /// </summary>
    public class Pkcs7CryptoSignatureVerifier : ICryptoSignatureVerifier
    {
        /// <see cref="ICryptoSignatureVerifier.Verify" />
        /// <exception cref="PkiVerificationException">thrown when signature verification throws any exception</exception>
        public void Verify(byte[] signedBytes, byte[] signatureBytes, Dictionary<string, object> data)
        {
            try
            {
                SignedCms signedCms = new SignedCms(new ContentInfo(signedBytes), true);
                signedCms.Decode(signatureBytes);
                signedCms.CheckSignature(false);
            }
            catch (Exception e)
            {
                throw new PkiVerificationException("Failed to verify PKCS#7 signature.", e);
            }
        }
    }
}