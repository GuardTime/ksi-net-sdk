using System;
using System.IO;
using Guardtime.KSI.Parser;
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
            using (var stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                var publicationsFile = PublicationsFile.GetInstance(stream);
            }
        }

        [Test]
        public void TestFindCertificateById()
        {
            using (var stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                var publicationsFile = PublicationsFile.GetInstance(stream);
                Assert.AreEqual("O=Guardtime, CN=H5", publicationsFile.FindCertificateById(new byte[] { 0x9a, 0x65, 0x82, 0x94 }).Subject, "Certificate should be correct");
            }
        }

        [Test]
        public void TestContainsPublicationRecord()
        {
            using (var stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            using (var reader = new TlvReader(new FileStream("resources/publication/publicationrecord/pub-record-18-09-2014.bin", FileMode.Open)))
            {
                var publicationsFile = PublicationsFile.GetInstance(stream);
                Assert.IsFalse(publicationsFile.Contains(null), "Should not crash when null object is used");

                Assert.IsTrue(publicationsFile.Contains(new PublicationRecord(reader.ReadTag())), "Should contain given publication record");
            }
        }

        [Test]
        public void TestDoesNotContainPublicationRecord()
        {
            using (var stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            using (var reader = new TlvReader(new FileStream("resources/publication/publicationrecord/pub-record-invalid-hash-18-09-2014.bin", FileMode.Open)))
            {
                var publicationsFile = PublicationsFile.GetInstance(stream);
                Assert.IsFalse(publicationsFile.Contains(new PublicationRecord(reader.ReadTag())), "Should contain given publication record");
            }
        }

        [Test]
        public void TestGetLatestPublication()
        {
            using (var stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                var publicationsFile = PublicationsFile.GetInstance(stream);
                var publicationRecord = publicationsFile.GetLatestPublication();

                Assert.AreEqual(1429056000, publicationRecord.PublicationData.PublicationTime.Value, "Should be correct publication time for latest publication");
                // TODO: Test more from latest publication
            }
        }
    }
}