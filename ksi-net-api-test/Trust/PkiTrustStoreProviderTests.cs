﻿/*
 * Copyright 2013-2018 Guardtime, Inc.
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
        public void PkiTrustStoreProviderCreateWithoutTrustStoreTest()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(null, null);
            });
            Assert.AreEqual("trustStore", ex.ParamName);
        }

        [Test]
        public void PkiTrustStoreProviderCreateWithoutCertificateRdnSelector()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(TestUtil.CreateCertStore(Resources.PkiTrustProvider_IdenTrustCert), null);
            });
            Assert.AreEqual("certificateRdnSelector", ex.ParamName);
        }

        [Test]
        public void PkiTrustStoreProviderVerifyWithoutSignedBytes()
        {
            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(TestUtil.CreateCertStore(Resources.PkiTrustProvider_IdenTrustCert),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                trustStoreProvider.Verify(null, null);
            });
            Assert.AreEqual("signedBytes", ex.ParamName);
        }

        [Test]
        public void PkiTrustStoreProviderVerifyWithoutSignatureBytes()
        {
            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(TestUtil.CreateCertStore(Resources.PkiTrustProvider_IdenTrustCert),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = TestUtil.GetPublicationsFile(Resources.KsiPublicationsFile);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), null);
            });
            Assert.AreEqual("signatureBytes", ex.ParamName);
        }

        [Test]
        public void PkiTrustStoreProviderVerifyTest()
        {
            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(TestUtil.CreateCertStore(Resources.PkiTrustProvider_IdenTrustCert),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = TestUtil.GetPublicationsFile(Resources.KsiPublicationsFile);

            trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
        }

        [Test]
        public void PkiTrustStoreProviderVerifyWithRootTest()
        {
            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = TestUtil.GetPublicationsFile(Resources.KsiPublicationsFile);

            trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
        }

        [Test]
        public void PkiTrustStoreProviderVerifyInvalidTest()
        {
            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(TestUtil.CreateCertStore(Resources.PkiTrustProvider_CustomCertInvalid),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = TestUtil.GetPublicationsFile(Resources.KsiPublicationsFile);

            PkiVerificationFailedException ex = Assert.Throws<PkiVerificationFailedException>(delegate
            {
                trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
            });

            // separate error messages for Microsoft and Bouncy Castle
            Assert.That(ex.Message.StartsWith("Trust chain did not complete to the known authority anchor. Thumbprints did not match.") ||
                        (ex.Message.StartsWith("Could not build certificate path") &&
                         ex.InnerException.Message.StartsWith("No issuer certificate for certificate in certification path found.")),
                "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void PkiTrustStoreProviderVerifyCustomCertTest()
        {
            // test verify with custom cert

            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(TestUtil.CreateCertStore(Resources.PkiTrustProvider_CustomCert),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = TestUtil.GetPublicationsFile(Resources.PkiTrustProvider_PubsFileCustomCert);

            trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
        }

        [Test]
        public void PkiTrustStoreProviderVerifCustomyWithRootInvalidTest()
        {
            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = TestUtil.GetPublicationsFile(Resources.PkiTrustProvider_PubsFileCustomCert);

            PkiVerificationFailedException ex = Assert.Throws<PkiVerificationFailedException>(delegate
            {
                trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
            });

            // separate error messages for Microsoft and Bouncy Castle
            Assert.That(ex.Message.StartsWith("Trust chain did not complete to the known authority anchor. Thumbprints did not match.") ||
                        (ex.Message.StartsWith("Could not build certificate path")
                         && ex.InnerException.Message.StartsWith("Unable to find certificate chain.")),
                "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void PkiTrustStoreProviderVerifyCustomCertMultiTest()
        {
            // test verify with custom cert

            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(
                TestUtil.CreateCertStore(Resources.PkiTrustProvider_CustomCert, Resources.PkiTrustProvider_CustomCertInvalid),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = TestUtil.GetPublicationsFile(Resources.PkiTrustProvider_PubsFileCustomCert);

            trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
        }

        [Test]
        public void PkiTrustStoreProviderVerifyCustomCertInvalidTest()
        {
            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(TestUtil.CreateCertStore(Resources.PkiTrustProvider_IdenTrustCert),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = TestUtil.GetPublicationsFile(Resources.PkiTrustProvider_PubsFileCustomCert);

            PkiVerificationFailedException ex = Assert.Throws<PkiVerificationFailedException>(delegate
            {
                trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
            });

            // separate error messages for Microsoft and Bouncy Castle
            Assert.That(ex.Message.StartsWith("Trust chain did not complete to the known authority anchor. Thumbprints did not match.") ||
                        (ex.Message.StartsWith("Could not build certificate path")
                         && ex.InnerException.Message.StartsWith("Unable to find certificate chain.")),
                "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void PkiTrustStoreProviderVerifyCustomCertMultiInvalidTest()
        {
            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(
                TestUtil.CreateCertStore(
                    Resources.PkiTrustProvider_CustomCertInvalid,
                    Resources.PkiTrustProvider_IdenTrustCert),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = TestUtil.GetPublicationsFile(Resources.PkiTrustProvider_PubsFileCustomCert);

            PkiVerificationFailedException ex = Assert.Throws<PkiVerificationFailedException>(delegate
            {
                trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
            });

            // separate error messages for Microsoft and Bouncy Castle
            Assert.That(ex.Message.StartsWith("Trust chain did not complete to the known authority anchor. Thumbprints did not match.") ||
                        (ex.Message.StartsWith("Could not build certificate path")
                         && ex.InnerException.Message.StartsWith("Unable to find certificate chain.")),
                "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void PkiTrustStoreProviderVerifyCustomCertExpiredInvalidTest()
        {
            PkiTrustStoreProvider trustStoreProvider = new PkiTrustStoreProvider(TestUtil.CreateCertStore(Resources.PkiTrustProvider_CustomCertExpired),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            PublicationsFile publicationsFile = TestUtil.GetPublicationsFile(Resources.PkiTrustProvider_PubsFileCustomCertExpired);

            PkiVerificationFailedException ex = Assert.Throws<PkiVerificationFailedException>(delegate
            {
                trustStoreProvider.Verify(publicationsFile.GetSignedBytes(), publicationsFile.GetSignatureValue());
            });

            // separate error messages for Microsoft and Bouncy Castle

            Assert.That(
                ex.Message.StartsWith(
                    "Trust chain did not complete to the known authority anchor. Errors: A required certificate is not within its validity period when verifying against the current system clock or the timestamp in the signed file.") ||
                (ex.Message.StartsWith("Could not build certificate path")
                 && ex.InnerException.Message.StartsWith("Certification path could not be validated.")
                 && ex.InnerException.InnerException.Message.StartsWith("Could not validate certificate: certificate expired on ")),
                "Unexpected exception message: " + ex.Message);
        }


    }
}