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
            var publicationsFile = PublicationsFile.GetInstance(new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open));
            Console.WriteLine(publicationsFile);
        }

        [Test]
        public void TestFindCertificateById()
        {
            var publicationsFile = PublicationsFile.GetInstance(new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open));
            Assert.AreEqual("O=Guardtime, CN=H5", publicationsFile.FindCertificateById(new byte[] { 0x9a, 0x65, 0x82, 0x94 }).Subject, "Certificate should be correct");
        }

        [Test]
        public void TestContainsPublicationRecord()
        {
            var publicationsFile = PublicationsFile.GetInstance(new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open));
            Assert.IsFalse(publicationsFile.Contains(null), "Should not crash when null object is used");

            using (
                var reader =
                    new TlvReader(new FileStream("resources/publication/publicationrecord/pub-record-18-09-2014.bin", FileMode.Open)))
            {
                Assert.IsTrue(publicationsFile.Contains(new PublicationRecord(reader.ReadTag())), "Should contain given publication record");
            }
        }

        [Test]
        public void TestDoesNotContainPublicationRecord()
        {
            var publicationsFile = PublicationsFile.GetInstance(new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open));

            using (
                var reader =
                    new TlvReader(new FileStream("resources/publication/publicationrecord/pub-record-invalid-hash-18-09-2014.bin", FileMode.Open)))
            {
                Assert.IsFalse(publicationsFile.Contains(new PublicationRecord(reader.ReadTag())), "Should contain given publication record");
            }
        }

        [Test]
        public void TestGetLatestPublication()
        {
            var publicationsFile = PublicationsFile.GetInstance(new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open));
            var publicationRecord = publicationsFile.GetLatestPublication();

            Assert.AreEqual(new DateTime(2015, 4, 15), publicationRecord.PublicationTime, "Should be correct publication time for latest publication");
            // TODO: Test more from latest publication
        }
    }
}