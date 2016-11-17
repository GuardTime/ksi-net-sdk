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
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Trust;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Trust
{
    [TestFixture]
    public class PkiTrustStoreProviderTests
    {
        [Test]
        public void PkiTrustStoreProviderVerifyTest()
        {
            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(CreateCertStore(Resources.PkiTrustProvider_SymantecCert),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = GetPublicationsFile(Resources.PkiTrustProvider_PubsFileSymantecCert);

            trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
        }

        [Test]
        public void PkiTrustStoreProviderVerifyWithRootTest()
        {
            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = GetPublicationsFile(Resources.PkiTrustProvider_PubsFileSymantecCert);

            trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
        }

        [Test]
        public void PkiTrustStoreProviderVerifyInvalidTest()
        {
            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(CreateCertStore(Resources.PkiTrustProvider_CustomCertInvalid),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = GetPublicationsFile(Resources.PkiTrustProvider_PubsFileSymantecCert);

            PkiVerificationFailedException ex = Assert.Throws<PkiVerificationFailedException>(delegate
            {
                trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
            });

            // separate error messages for Microsoft and Bouncy Castle
            Assert.That(ex.Message.StartsWith("Trust chain did not complete to the known authority anchor. Thumbprints did not match.") ||
                        (ex.Message.StartsWith("Could not building certificate path") &&
                         ex.InnerException.Message.StartsWith("No issuer certificate for certificate in certification path found.")),
                "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void PkiTrustStoreProviderVerifyCustomCertTest()
        {
            // test verify with custom cert

            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(CreateCertStore(Resources.PkiTrustProvider_CustomCert),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = GetPublicationsFile(Resources.PkiTrustProvider_PubsFileCustomCert);

            trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
        }

        [Test]
        public void PkiTrustStoreProviderVerifCustomyWithRootInvalidTest()
        {
            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = GetPublicationsFile(Resources.PkiTrustProvider_PubsFileCustomCert);

            PkiVerificationFailedException ex = Assert.Throws<PkiVerificationFailedException>(delegate
            {
                trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
            });

            // separate error messages for Microsoft and Bouncy Castle
            Assert.That(ex.Message.StartsWith("Trust chain did not complete to the known authority anchor. Thumbprints did not match.") ||
                        ex.Message.StartsWith("Could not building certificate path"),
                "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void PkiTrustStoreProviderVerifyCustomCertMultiTest()
        {
            // test verify with custom cert

            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(
                CreateCertStore(Resources.PkiTrustProvider_CustomCert, Resources.PkiTrustProvider_CustomCertInvalid),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = GetPublicationsFile(Resources.PkiTrustProvider_PubsFileCustomCert);

            trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
        }

        [Test]
        public void PkiTrustStoreProviderVerifyCustomCertInvalidTest()
        {
            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(CreateCertStore(Resources.PkiTrustProvider_SymantecCert),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = GetPublicationsFile(Resources.PkiTrustProvider_PubsFileCustomCert);

            PkiVerificationFailedException ex = Assert.Throws<PkiVerificationFailedException>(delegate
            {
                trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
            });

            // separate error messages for Microsoft and Bouncy Castle
            Assert.That(ex.Message.StartsWith("Trust chain did not complete to the known authority anchor. Thumbprints did not match.") ||
                        ex.Message.StartsWith("Could not building certificate path"),
                "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void PkiTrustStoreProviderVerifyCustomCertMultiInvalidTest()
        {
            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(
                CreateCertStore(Resources.PkiTrustProvider_CustomCertInvalid, Resources.PkiTrustProvider_SymantecCert),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = GetPublicationsFile(Resources.PkiTrustProvider_PubsFileCustomCert);

            PkiVerificationFailedException ex = Assert.Throws<PkiVerificationFailedException>(delegate
            {
                trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
            });

            // separate error messages for Microsoft and Bouncy Castle
            Assert.That(ex.Message.StartsWith("Trust chain did not complete to the known authority anchor. Thumbprints did not match.") ||
                        ex.Message.StartsWith("Could not building certificate path"),
                "Unexpected exception message: " + ex.Message);
        }

        private static PublicationsFile GetPublicationsFile(string path)
        {
            byte[] pubsFileBytes = File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, path));
            byte[] data = new byte[pubsFileBytes.Length - PublicationsFile.FileBeginningMagicBytes.Length];
            Array.Copy(pubsFileBytes, PublicationsFile.FileBeginningMagicBytes.Length, data, 0, data.Length);

            return new PublicationsFile(new RawTag(0x0, false, false, data));
        }

        public X509Store CreateCertStore(params string[] certPaths)
        {
            X509Store store = new X509Store("test", StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            store.RemoveRange(store.Certificates);

            foreach (string certPath in certPaths)
            {
                X509Certificate2 certificate = new X509Certificate2(Path.Combine(TestSetup.LocalPath, certPath));
                store.Add(certificate);
            }
            return store;
        }
    }
}