using System;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Guardtime.KSI.Trust
{
    public class PkiTrustStoreProvider : IPkiTrustProvider
    {

        public string Name { get; }
        public void Verify(byte[] signedBytes, byte[] x509SignatureBytes)
        {
            if (x509SignatureBytes == null)
            {
                throw new ArgumentNullException("x509SignatureBytes");
            }

            // TODO: Java API email verification does not check email correctly, if its missing then it skips it
            var signedCms = new SignedCms(new ContentInfo(signedBytes), true);
            signedCms.Decode(x509SignatureBytes);
            signedCms.CheckSignature(false);
            Console.WriteLine(signedCms.SignerInfos[0].Certificate.GetNameInfo(X509NameType.EmailName, false));
        }
    }
}
