using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Exceptions;
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
        public void TestCreatePublicationsFileFromFile1()
        {
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    new CertificateSubjectRdnSelector("E=publications@guardtime.com"))).Create(stream);
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFile2()
        {
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    new CertificateSubjectRdnSelector("EMail=publications@guardtime.com"))).Create(stream);
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFile3()
        {
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    new CertificateSubjectRdnSelector("1.2.840.113549.1.9.1=publications@guardtime.com"))).Create(stream);
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFile4()
        {
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                ArgumentException ex = Assert.Throws<ArgumentException>(delegate
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        new CertificateSubjectRdnSelector("EEE=publications@guardtime.com"))).Create(stream);
                });

                Assert.That(ex.Message, Is.StringContaining("is invalid."));
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFile5()
        {
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                PublicationsFileException ex = Assert.Throws<PublicationsFileException>(delegate
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        new CertificateSubjectRdnSelector("E=Xpublications@guardtime.com"))).Create(stream);
                });

                Assert.That(ex.Message, Is.StringStarting("Publications file verification failed."));
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFile6()
        {
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                PublicationsFileException ex = Assert.Throws<PublicationsFileException>(delegate
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        new CertificateSubjectRdnSelector("1.2.840.113549.1.9.1=Xpublications@guardtime.com"))).Create(stream);
                });

                Assert.That(ex.Message, Is.StringStarting("Publications file verification failed."));
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFile7()
        {
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                ArgumentException ex = Assert.Throws<ArgumentException>(delegate
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        new CertificateSubjectRdnSelector(new List<CertificateSubjectRdn> { new CertificateSubjectRdn("1.2.840.113549.1.9.1X", "publications@guardtime.com") })))
                        .Create(stream);
                });

                Assert.That(ex.Message, Is.StringStarting("Rdn contains invalid Oid or Value."));
            }
        }

        [Test]
        public void TestFindCertificateById()
        {
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                IPublicationsFile publicationsFile =
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        new CertificateSubjectRdnSelector("E=publications@guardtime.com"))).Create(stream);
                Assert.AreEqual("O=Guardtime, CN=H5", new X509Certificate2(publicationsFile.FindCertificateById(new byte[] { 0x9a, 0x65, 0x82, 0x94 })).Subject,
                    "Certificate should be correct");
            }
        }

        [Test]
        public void TestContainsPublicationRecord()
        {
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                using (TlvReader reader = new TlvReader(new FileStream("resources/publication/publicationrecord/pub-record-18-09-2014.bin", FileMode.Open)))
                {
                    IPublicationsFile publicationsFile =
                        new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                            new CertificateSubjectRdnSelector("E=publications@guardtime.com"))).Create(stream);
                    Assert.IsFalse(publicationsFile.Contains(null), "Should not crash when null object is used");

                    Assert.IsTrue(publicationsFile.Contains(new PublicationRecordInPublicationFile(reader.ReadTag())), "Should contain given publication record");
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
                    IPublicationsFile publicationsFile =
                        new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                            new CertificateSubjectRdnSelector("E=publications@guardtime.com"))).Create(stream);
                    Assert.IsFalse(publicationsFile.Contains(new PublicationRecordInPublicationFile(reader.ReadTag())), "Should not contain given publication record");
                }
            }
        }

        [Test]
        public void TestGetLatestPublication()
        {
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                IPublicationsFile publicationsFile =
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        new CertificateSubjectRdnSelector("E=publications@guardtime.com"))).Create(stream);
                PublicationRecordInPublicationFile publicationRecord = publicationsFile.GetLatestPublication();

                Assert.AreEqual(1442275200, publicationRecord.PublicationData.PublicationTime, "Should be correct publication time for latest publication");
                // TODO: Test more from latest publication
            }
        }
    }
}