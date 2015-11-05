using System.Security.Cryptography.Pkcs;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Trust
{
    /// <summary>
    ///     PKI trust store provider.
    /// </summary>
    public class PkiTrustStoreProvider : IPkiTrustProvider
    {
        /// <summary>
        ///     Verify bytes with x509 signature.
        /// </summary>
        /// <param name="signedBytes"></param>
        /// <param name="signatureBytes"></param>
        /// <exception cref="PkiVerificationException">thrown when invalid data is supplied or verification failed</exception>
        public void Verify(byte[] signedBytes, byte[] signatureBytes)
        {
            // TODO: Check for better exception
            if (signedBytes == null)
            {
                throw new PkiVerificationException("Invalid signed bytes: null.");
            }

            if (signatureBytes == null)
            {
                throw new PkiVerificationException("Invalid signature bytes: null.");
            }

            ICryptoSignatureVerifier verifier = CryptoSignatureVerifierFactory.Pkcs7SignatureVerifier;
            verifier.Verify(signedBytes, signatureBytes, null);

            SignedCms signedCms = new SignedCms(new ContentInfo(signedBytes), true);
            signedCms.Decode(signatureBytes);

            // TODO: Verify email also
            //Console.WriteLine(signedCms.SignerInfos[0].Certificate.GetNameInfo(X509NameType.EmailName, false));
        }
    }
}