using System;
using System.Collections.Generic;
using System.Security.Cryptography.Pkcs;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Crypto
{
    /// <summary>
    /// PKCS#7 signature verifier.
    /// </summary>
    public class Pkcs7CryptoSignatureVerifier : ICryptoSignatureVerifier
    {
        /// <see cref="ICryptoSignatureVerifier"/>
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
                // TODO: Better exception
                throw new KsiException("Verification failed", e);
            }
        }
    }
}