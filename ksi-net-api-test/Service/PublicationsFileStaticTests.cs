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
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Trust;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    /// <summary>
    /// Publications file tests with static response
    /// </summary>
    [TestFixture]
    public class PublicationsFileStaticTests : StaticServiceTestsBase
    {
        /// <summary>
        /// Test signing and verifying
        /// </summary>
        [Test]
        public void GetPublicationsFileStaticTest()
        {
            Ksi ksi = GetKsi();

            IPublicationsFile pubFile = ksi.GetPublicationsFile();
            Assert.AreEqual(1515974400, pubFile.GetLatestPublication().PublicationData.PublicationTime, "Unexpected last publication time");
        }

        [Test]
        public void BeginGetPublicationsFileWithoutPublicationsFileServiceProtocol()
        {
            KsiService service = new KsiService(null, null, null, null, null, null);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.BeginGetPublicationsFile(null, null);
            });

            Assert.That(ex.Message.StartsWith("Publications file service protocol is missing from service"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void EndGetPublicationsFileWithAsyncResultNullTest()
        {
            KsiService service = GetKsiService();

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                service.EndGetPublicationsFile(null);
            });
            Assert.AreEqual("asyncResult", ex.ParamName);
        }

        [Test]
        public void EndGetPublicationsFileInvalidAsyncResultTest()
        {
            KsiService service = GetKsiService();

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.EndGetPublicationsFile(new TestAsyncResult());
            });

            Assert.That(ex.Message.StartsWith("Invalid asyncResult type:"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void EndGetPublicationsFileWithoutPublicationsFileServiceProtocol()
        {
            KsiService service = new KsiService(null, null, null, null, null, null);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.EndGetPublicationsFile(new TestAsyncResult());
            });

            Assert.That(ex.Message.StartsWith("Publications file service protocol is missing from service"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void EndGetPublicationsFileWithoutPublicationsFileFactory()
        {
            KsiService service = new KsiService(null, null, null, null, new TestKsiServiceProtocol(), null);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.EndGetPublicationsFile(new TestAsyncResult());
            });

            Assert.That(ex.Message.StartsWith("Publications file factory is missing from service"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void HttpKsiServiceProtocolEndGetPublicationsFileInvalidAsyncResultTest()
        {
            HttpKsiServiceProtocol protocol = new HttpKsiServiceProtocol(null, null, null);

            KsiServiceProtocolException ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                protocol.EndGetPublicationsFile(new TestAsyncResult());
            });

            Assert.That(ex.Message.StartsWith("Invalid IAsyncResult"), "Unexpected exception message: " + ex.Message);
        }

        private static Ksi GetKsi()
        {
            return new Ksi(GetKsiService());
        }

        private static KsiService GetKsiService()
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol();

            return new KsiService(protocol, new ServiceCredentials("test", "test", HashAlgorithm.Sha2256), protocol, new ServiceCredentials("test", "test", HashAlgorithm.Sha2256),
                protocol,
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))));
        }
    }
}