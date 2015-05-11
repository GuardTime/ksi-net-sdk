using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Guardtime.KSI.Trust
{
    [TestClass()]
    public class PkiTrustStoreProviderTests
    {
        [TestMethod()]
        public void VerifyTest()
        {
            byte[] data;
            using (var stream = new FileStream("resources/trust/pkitrustprovider/data.bin", FileMode.Open))
            {
                data = new byte[stream.Length];
                stream.Read(data, 0, (int) stream.Length);
            }

            byte[] sigBytes;
            using (var stream = new FileStream("resources/trust/pkitrustprovider/sigbytes.bin", FileMode.Open))
            {
                sigBytes = new byte[stream.Length];
                stream.Read(sigBytes, 0, (int)stream.Length);
            }

            new PkiTrustStoreProvider().Verify(data, sigBytes);
        }
    }
}