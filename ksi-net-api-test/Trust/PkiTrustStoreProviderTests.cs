using System.IO;
using Guardtime.KSI.Exceptions;
using NUnit.Framework;

namespace Guardtime.KSI.Trust
{
    [TestFixture]
    public class PkiTrustStoreProviderTests
    {
        [Test]
        public void VerifyTest()
        {
            byte[] data;
            using (FileStream stream = new FileStream("resources/trust/pkitrustprovider/data.bin", FileMode.Open))
            {
                data = new byte[stream.Length];
                stream.Read(data, 0, (int)stream.Length);
            }

            byte[] sigBytes;
            using (FileStream stream = new FileStream("resources/trust/pkitrustprovider/sigbytes.bin", FileMode.Open))
            {
                sigBytes = new byte[stream.Length];
                stream.Read(sigBytes, 0, (int)stream.Length);
            }

            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider();

            trustStoreProvider.Verify(data, sigBytes);

            Assert.Throws<PkiVerificationException>(delegate
            {
                trustStoreProvider.Verify(null, sigBytes);
            });

            Assert.Throws<PkiVerificationException>(delegate
            {
                trustStoreProvider.Verify(data, null);
            });
        }
    }
}