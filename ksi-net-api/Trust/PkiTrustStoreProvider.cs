using System;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Guardtime.KSI.Trust
{
    /// <summary>
    /// PKI trust store provider.
    /// </summary>
    public class PkiTrustStoreProvider : IPkiTrustProvider
    {
        /// <summary>
        /// Return PKI trust store provider name.
        /// </summary>
        public string Name
        {
            // TODO: Correct return
            get { return ""; } 
        }

        /// <summary>
        /// Verify bytes with x509 signature.
        /// </summary>
        /// <param name="signedBytes"></param>
        /// <param name="x509SignatureBytes"></param>
        public void Verify(byte[] signedBytes, byte[] x509SignatureBytes)
        {
            if (x509SignatureBytes == null)
            {
                throw new ArgumentNullException("x509SignatureBytes");
            }
            
            SignedCms signedCms = new SignedCms(new ContentInfo(signedBytes), true);
            signedCms.Decode(x509SignatureBytes);
            signedCms.CheckSignature(false);

            // TODO: Verify email also
            Console.WriteLine(signedCms.SignerInfos[0].Certificate.GetNameInfo(X509NameType.EmailName, false));
        }
    }
}
