using System;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;

namespace Guardtime.KSI.Trust
{
    /// <summary>
    /// PKI trust store provider.
    /// </summary>
    public class PkiTrustStoreProvider : IPkiTrustProvider
    {
        /// <summary>
        /// Verify bytes with x509 signature.
        /// </summary>
        /// <param name="signedBytes"></param>
        /// <param name="signatureBytes"></param>
        public void Verify(byte[] signedBytes, byte[] signatureBytes)
        {
            if (signatureBytes == null)
            {
                throw new ArgumentNullException("signatureBytes");
            }

            ICryptoSignatureVerifier verifier = CryptoSignatureVerifierFactory.Pkcs7SignatureVerifier;
            verifier.Verify(signedBytes, signatureBytes, null);

            SignedCms signedCms = new SignedCms(new ContentInfo(signedBytes), true);
            signedCms.Decode(signatureBytes);

            // TODO: Verify email also
            Console.WriteLine(signedCms.SignerInfos[0].Certificate.GetNameInfo(X509NameType.EmailName, false));
        }
    }
}
