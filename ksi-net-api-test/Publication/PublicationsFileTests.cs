using System.IO;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Trust;
using NUnit.Framework;

namespace Guardtime.KSI.Publication
{
    // TODO: Possibility to change file easily because signature certificate expires
    [TestFixture]
    public class PublicationsFileTests
    {
        [Test]
        public void TestCreatePublicationsFileFromFile()
        {
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(TrustStoreUtilities.GetTrustAnchorCollection(), new CertificateRdnSubjectSelector("E=publications@guardtime.com"))).Create(stream);
            }
        }

        [Test]
        public void TestFindCertificateById()
        {
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                IPublicationsFile publicationsFile = new PublicationsFileFactory(new PkiTrustStoreProvider(TrustStoreUtilities.GetTrustAnchorCollection(), new CertificateRdnSubjectSelector("E=publications@guardtime.com"))).Create(stream);
                Assert.AreEqual("O=Guardtime, CN=H5", new X509Certificate2(publicationsFile.FindCertificateById(new byte[] {0x9a, 0x65, 0x82, 0x94})).Subject, "Certificate should be correct");
            }
        }

        [Test]
        public void TestContainsPublicationRecord()
        {
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                using (TlvReader reader = new TlvReader(new FileStream("resources/publication/publicationrecord/pub-record-18-09-2014.bin", FileMode.Open)))
                {
                    IPublicationsFile publicationsFile = new PublicationsFileFactory(new PkiTrustStoreProvider(TrustStoreUtilities.GetTrustAnchorCollection(), new CertificateRdnSubjectSelector("E=publications@guardtime.com"))).Create(stream);
                    Assert.IsFalse(publicationsFile.Contains(null), "Should not crash when null object is used");

                    Assert.IsTrue(publicationsFile.Contains(new PublicationRecord(reader.ReadTag())), "Should contain given publication record");
                }
            }
        }

        [Test]
        public void TestDoesNotContainPublicationRecord()
        {
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                using (TlvReader reader = new TlvReader(new FileStream("resources/publication/publicationrecord/pub-record-invalid-hash-18-09-2014.bin", FileMode.Open)))
                {
                    IPublicationsFile publicationsFile = new PublicationsFileFactory(new PkiTrustStoreProvider(TrustStoreUtilities.GetTrustAnchorCollection(), new CertificateRdnSubjectSelector("E=publications@guardtime.com"))).Create(stream);
                    Assert.IsFalse(publicationsFile.Contains(new PublicationRecord(reader.ReadTag())), "Should contain given publication record");
                }
            }
        }

        [Test]
        public void TestGetLatestPublication()
        {
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                IPublicationsFile publicationsFile = new PublicationsFileFactory(new PkiTrustStoreProvider(TrustStoreUtilities.GetTrustAnchorCollection(), new CertificateRdnSubjectSelector("E=publications@guardtime.com"))).Create(stream);
                PublicationRecord publicationRecord = publicationsFile.GetLatestPublication();

                Assert.AreEqual(1442275200, publicationRecord.PublicationData.PublicationTime, "Should be correct publication time for latest publication");
                // TODO: Test more from latest publication
            }
        }
    }
}