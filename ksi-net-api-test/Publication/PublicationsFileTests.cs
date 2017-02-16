/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Trust;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Publication
{
    [TestFixture]
    public class PublicationsFileTests
    {
        [Test]
        public void TestCreatePublicationsFileFromFileEmail()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))).Create(stream);
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFileOu()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector("OU=Verified Email: publications@guardtime.com"))).Create(stream);
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFileLongEmailName()
        {
            if (CryptoTestFactory.ProviderType == CryptoProviderType.BouncyCastle)
            {
                using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("EmailAddress=publications@guardtime.com"))).Create(stream);
                }
            }
            else if (CryptoTestFactory.ProviderType == CryptoProviderType.Microsoft)
            {
                using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("EMail=publications@guardtime.com"))).Create(stream);
                }
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFileWithOid()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector("1.2.840.113549.1.9.1=publications@guardtime.com"))).Create(stream);
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFileInvalidName()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                ArgumentException ex = Assert.Throws<ArgumentException>(delegate
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("EEE=publications@guardtime.com"))).Create(stream);
                });

                Assert.That(ex.Message, Does.Contain("is invalid.") | Does.Contain("Unknown object id"));
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFileInvalidEmail()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                PublicationsFileException ex = Assert.Throws<PublicationsFileException>(delegate
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=Xpublications@guardtime.com"))).Create(stream);
                });

                Assert.That(ex.Message, Does.StartWith("Publications file verification failed."));
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFileInvalidOu()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                PublicationsFileException ex = Assert.Throws<PublicationsFileException>(delegate
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("OU=something"))).Create(stream);
                });

                Assert.That(ex.Message, Does.StartWith("Publications file verification failed."));
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFileInvalidEmailWithOid()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                PublicationsFileException ex = Assert.Throws<PublicationsFileException>(delegate
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("1.2.840.113549.1.9.1=Xpublications@guardtime.com"))).Create(stream);
                });

                Assert.That(ex.Message, Does.StartWith("Publications file verification failed."));
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFileInvalidOid()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                ArgumentException ex = Assert.Throws<ArgumentException>(delegate
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector(new List<CertificateSubjectRdn>
                        {
                            new CertificateSubjectRdn("1.2.840.113549.1.9.1X", "publications@guardtime.com")
                        })))
                        .Create(stream);
                });

                Assert.That(ex.Message, Does.StartWith("Rdn contains invalid Oid or Value."));
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFileMultipleRdns()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector(new List<CertificateSubjectRdn>
                    {
                        new CertificateSubjectRdn("1.2.840.113549.1.9.1", "publications@guardtime.com"),
                        new CertificateSubjectRdn("OU", "Verified Email: publications@guardtime.com")
                    })))
                    .Create(stream);
            }
        }

        [Test]
        public void TestCreatePublicationsFileFromFileMultipleRdnsInvalidOu()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                PublicationsFileException ex = Assert.Throws<PublicationsFileException>(delegate
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector(new List<CertificateSubjectRdn>
                        {
                            new CertificateSubjectRdn("1.2.840.113549.1.9.1", "publications@guardtime.com"),
                            new CertificateSubjectRdn("OU", "something")
                        })))
                        .Create(stream);
                });

                Assert.That(ex.Message, Does.StartWith("Publications file verification failed"));
            }
        }

        [Test]
        public void TestFindCertificateById()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                IPublicationsFile publicationsFile =
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))).Create(stream);

                Assert.AreEqual("O=Guardtime, CN=H5", new X509Certificate2(publicationsFile.FindCertificateById(new byte[] { 0x9a, 0x65, 0x82, 0x94 })).Subject,
                    "Certificate should be correct");
            }
        }

        [Test]
        public void TestGetLatestPublication()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                IPublicationsFile publicationsFile =
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))).Create(stream);
                PublicationRecordInPublicationFile publicationRecord = publicationsFile.GetLatestPublication();

                Assert.AreEqual(1484438400, publicationRecord.PublicationData.PublicationTime, "Should be correct publication time for latest publication");
            }
        }

        [Test]
        public void ToStringTest()
        {
            PublicationsFile tag =
                TestUtil.GetCompositeTag<PublicationsFile>(0x0,
                    new ITlvTag[]
                    {
                        TestUtil.GetCompositeTag<PublicationsFileHeader>(Constants.PublicationsFileHeader.TagType,
                            new ITlvTag[]
                            {
                                new IntegerTag(Constants.PublicationsFileHeader.VersionTagType, false, false, 1),
                                new IntegerTag(Constants.PublicationsFileHeader.CreationTimeTagType, false, false, 2),
                                new StringTag(Constants.PublicationsFileHeader.RepositoryUriTagType, false, false, "Test repository uri"),
                            }),
                        TestUtil.GetCompositeTag<CertificateRecord>(Constants.CertificateRecord.TagType,
                            new ITlvTag[]
                            {
                                new RawTag(Constants.CertificateRecord.CertificateIdTagType, false, false, new byte[] { 0x2 }),
                                new RawTag(Constants.CertificateRecord.X509CertificateTagType, false, false, new byte[] { 0x3 }),
                            }),
                        TestUtil.GetCompositeTag<CertificateRecord>(Constants.CertificateRecord.TagType,
                            new ITlvTag[]
                            {
                                new RawTag(Constants.CertificateRecord.CertificateIdTagType, false, false, new byte[] { 0x4 }),
                                new RawTag(Constants.CertificateRecord.X509CertificateTagType, false, false, new byte[] { 0x5 }),
                            }),
                        TestUtil.GetCompositeTag<PublicationRecordInPublicationFile>(Constants.PublicationRecord.TagTypeInPublicationsFile,
                            new ITlvTag[]
                            {
                                TestUtil.GetCompositeTag<PublicationData>(Constants.PublicationData.TagType,
                                    new ITlvTag[]
                                    {
                                        new IntegerTag(Constants.PublicationData.PublicationTimeTagType, false, false, 1),
                                        new ImprintTag(Constants.PublicationData.PublicationHashTagType, false, false,
                                            new DataHash(HashAlgorithm.Sha2256,
                                                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                                    }),
                                new StringTag(Constants.PublicationRecord.PublicationReferencesTagType, false, false, "Test publication reference 1"),
                                new StringTag(Constants.PublicationRecord.PublicationReferencesTagType, false, false, "Test publication reference 2"),
                                new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test publication repository uri 1"),
                                new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test publication repository uri 2"),
                            }),
                        TestUtil.GetCompositeTag<PublicationRecordInPublicationFile>(Constants.PublicationRecord.TagTypeInPublicationsFile,
                            new ITlvTag[]
                            {
                                TestUtil.GetCompositeTag<PublicationData>(Constants.PublicationData.TagType,
                                    new ITlvTag[]
                                    {
                                        new IntegerTag(Constants.PublicationData.PublicationTimeTagType, false, false, 1),
                                        new ImprintTag(Constants.PublicationData.PublicationHashTagType, false, false,
                                            new DataHash(HashAlgorithm.Sha2256,
                                                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                                    }),
                                new StringTag(Constants.PublicationRecord.PublicationReferencesTagType, false, false, "Test publication reference 3"),
                                new StringTag(Constants.PublicationRecord.PublicationReferencesTagType, false, false, "Test publication reference 4"),
                                new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test publication repository uri 5"),
                                new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test publication repository uri 6"),
                            }),
                        new RawTag(Constants.PublicationsFile.CmsSignatureTagType, false, false, new byte[] { 0x3 }),
                    });

            PublicationsFile tag2 = new PublicationsFile(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString(), "PublicationsFiles' strings should match");

            for (int i = 0; i < tag.Count; i++)
            {
                Assert.AreEqual(tag[i].ToString(), tag2[i].ToString(), string.Format("Tags do not match. Index: {0}", i));
            }

            Assert.AreEqual(@"TLV[0x701]:
  TLV[0x1]:i1
  TLV[0x2]:i2
  TLV[0x3]:""Test repository uri""", tag[0].ToString(), "Invalid string for tag. Index: 0");

            Assert.AreEqual(@"TLV[0x702]:
  TLV[0x1]:0x02
  TLV[0x2]:0x03", tag[1].ToString(), "Invalid string for tag. Index: 1");

            Assert.AreEqual(@"TLV[0x702]:
  TLV[0x1]:0x04
  TLV[0x2]:0x05", tag[2].ToString(), "Invalid string for tag. Index: 2");

            Assert.AreEqual(@"TLV[0x703]:
  TLV[0x10]:
    TLV[0x2]:i1
    TLV[0x4]:0x010102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
  TLV[0x9]:""Test publication reference 1""
  TLV[0x9]:""Test publication reference 2""
  TLV[0xA]:""Test publication repository uri 1""
  TLV[0xA]:""Test publication repository uri 2""", tag[3].ToString(), "Invalid string for tag. Index: 3");

            Assert.AreEqual(@"TLV[0x703]:
  TLV[0x10]:
    TLV[0x2]:i1
    TLV[0x4]:0x010102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
  TLV[0x9]:""Test publication reference 3""
  TLV[0x9]:""Test publication reference 4""
  TLV[0xA]:""Test publication repository uri 5""
  TLV[0xA]:""Test publication repository uri 6""", tag[4].ToString(), "Invalid string for tag. Index: 4");

            Assert.AreEqual(@"TLV[0x704]:0x03", tag[5].ToString(), "Invalid string for tag. Index: 5");
        }
    }
}