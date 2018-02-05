/*
 * Copyright 2013-2017 Guardtime, Inc.
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
using Guardtime.KSI.Publication;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Trust;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Publication
{
    [TestFixture]
    public class PublicationsFileFactoryTests
    {
        [Test]
        public void CreatePublicationsFileWithTrustProviderNull()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new PublicationsFileFactory(null);
            });

            Assert.AreEqual("pkiTrustProvider", ex.ParamName, "Unexpected exception.");
        }

        [Test]
        public void CreatePublicationsFileWithStreamNull()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))).Create((Stream)null);
            });

            Assert.AreEqual("stream", ex.ParamName, "Unexpected exception.");
        }

        [Test]
        public void CreatePublicationsFileWithBytesNull()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))).Create((byte[])null);
            });

            Assert.AreEqual("bytes", ex.ParamName, "Unexpected exception.");
        }

        [Test]
        public void CreatePublicationsFileFromFileWithEmail()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))).Create(stream);
            }
        }

        [Test]
        public void CreatePublicationsFileFromFileWithOu()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector("OU=Verified Email: publications@guardtime.com"))).Create(stream);
            }
        }

        [Test]
        public void CreatePublicationsFileFromFileWithLongEmailName()
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
        public void CreatePublicationsFileFromFileWithOid()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector("1.2.840.113549.1.9.1=publications@guardtime.com"))).Create(stream);
            }
        }

        [Test]
        public void CreatePublicationsFileFromFileWithoutRdn()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                ArgumentException ex = Assert.Throws<ArgumentException>(delegate
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector())).Create(stream);
                });

                Assert.That(ex.Message, Does.StartWith("At least one RDN must be given"));
            }
        }

        [Test]
        public void CreatePublicationsFileFromFileWithEmptyRdn()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                ArgumentException ex = Assert.Throws<ArgumentException>(delegate
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector(""))).Create(stream);
                });

                Assert.That(ex.Message, Does.StartWith("RDN cannot be empty"));
            }
        }

        [Test]
        public void CreatePublicationsFileFromFileWithInvalidName()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                ArgumentException ex = Assert.Throws<ArgumentException>(delegate
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("EEE=publications@guardtime.com"))).Create(stream);
                });

                // separate error messages for microsoft and bouncycastle crypto
                Assert.That(ex.Message, Does.StartWith("Invalid RDN:") | Does.Contain("Unknown object id"));
            }
        }

        [Test]
        public void CreatePublicationsFileFromFileWithInvalidEmail()
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
        public void CreatePublicationsFileFromFileWithInvalidOu()
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
        public void CreatePublicationsFileFromFileWithOidAndInvalidEmail()
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
        public void CreatePublicationsFileFromFileWithInvalidOid()
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
        public void CreatePublicationsFileFromFileWithInvalidOidInRdnString()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                Exception ex = Assert.Catch<Exception>(delegate
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                            CryptoTestFactory.CreateCertificateSubjectRdnSelector("1.2.840.113549.1.9.1X=publications@guardtime.com")))
                        .Create(stream);
                });

                // separate error messages for microsoft and bouncycastle crypto
                Assert.That(ex.Message, Does.StartWith("Invalid RDN:") | Does.Contain("not an OID"));
            }
        }

        [Test]
        public void CreatePublicationsFileFromFileWithInvalidRdnString()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                Exception ex = Assert.Catch<Exception>(delegate
                {
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                            CryptoTestFactory.CreateCertificateSubjectRdnSelector("something")))
                        .Create(stream);
                });

                // separate error messages for microsoft and bouncycastle crypto
                Assert.That(ex.Message, Does.StartWith("Invalid RDN:") | Does.Contain("badly formated"));
            }
        }

        [Test]
        public void CreatePublicationsFileFromFileWithMultipleRdnStrings()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("1.2.840.113549.1.9.1=publications@guardtime.com", "OU=Verified Email: publications@guardtime.com")))
                    .Create(stream);
            }
        }

        [Test]
        public void CreatePublicationsFileFromFileWithMultipleSameRdnString()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("1.2.840.113549.1.9.1=publications@guardtime.com",
                            "1.2.840.113549.1.9.1=publications@guardtime.com")))
                    .Create(stream);
            }
        }

        [Test]
        public void CreatePublicationsFileFromFileWithMultipleRdnStringsOnOneField()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("1.2.840.113549.1.9.1=publications@guardtime.com,OU=Verified Email: publications@guardtime.com")))
                    .Create(stream);
            }
        }

        [Test]
        public void CreatePublicationsFileFromFileWithMultipleRdns()
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
        public void CreatePublicationsFileFromFileWithMultipleRdnsInvalidOu()
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
    }
}