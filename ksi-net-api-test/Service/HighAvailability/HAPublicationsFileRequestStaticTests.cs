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

using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Service.HighAvailability;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Trust;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service.HighAvailability
{
    /// <summary>
    /// High availability service publications file request tests with static response
    /// </summary>
    [TestFixture]
    public class HAPublicationsFileRequestStaticTests : StaticServiceTestsBase
    {
        /// <summary>
        /// Test publications file request without publications file services.
        /// </summary>
        [Test]
        public void HAPublicationsFileRequestWithoutServicesFailTest()
        {
            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetPublicationsFileService()
                    },
                    new List<IKsiService>()
                    {
                        GetPublicationsFileService()
                    },
                    null);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.GetPublicationsFile();
            });

            Assert.That(ex.Message.StartsWith("Publications file service is missing"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test ending publications file request without publications file services.
        /// </summary>
        [Test]
        public void HAEndPublicationsFileRequestWithoutServicesFailTest()
        {
            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetPublicationsFileService()
                    },
                    new List<IKsiService>()
                    {
                        GetPublicationsFileService()
                    },
                    null);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.EndGetPublicationsFile(new TestAsyncResult());
            });

            Assert.That(ex.Message.StartsWith("Publications file service is missing"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test publications file request
        /// </summary>
        [Test]
        public void HAPublicationsFileRequestTest()
        {
            IKsiService haService =
                new HAKsiService(
                    null,
                    null,
                    GetPublicationsFileService()
                );

            Assert.AreEqual("test.publications.file.address", haService.PublicationsFileAddress,
                "Unexpected publications file address.");

            IPublicationsFile publicationsFile = haService.GetPublicationsFile();
            Assert.AreEqual(1515974400, publicationsFile.GetLatestPublication().PublicationData.PublicationTime, "Unexpected last publication time");
        }

        /// <summary>
        /// Test publications file request with invalid request.
        /// </summary>
        [Test]
        public void HAPublicationsFileRequestFailTest()
        {
            IKsiService haService =
                new HAKsiService(
                    null,
                    null,
                    GetPublicationsFileService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)))
                );

            PublicationsFileException ex = Assert.Throws<PublicationsFileException>(delegate
            {
                haService.GetPublicationsFile();
            });

            Assert.That(ex.Message, Does.StartWith("Publications file header is incorrect. Invalid publications file magic bytes"));
        }

        public IKsiService GetPublicationsFileService(byte[] requestResult = null)
        {
            return new TestKsiService(
                null, null, null, null,
                new TestKsiServiceProtocol { PublicationsFileBytes = requestResult },
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))), 0, PduVersion.v1);
        }
    }
}