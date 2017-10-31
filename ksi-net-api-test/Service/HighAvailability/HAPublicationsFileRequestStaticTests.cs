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
    /// High availability publications file request tests with static response
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
                        GetPublicationsFileService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile)))
                    },
                    new List<IKsiService>()
                    {
                        GetPublicationsFileService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile)))
                    },
                    null);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.GetPublicationsFile();
            });

            Assert.That(ex.Message.StartsWith("Sub-services are missing"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test publications file request with single sub-service
        /// </summary>
        [Test]
        public void HAPublicationsFileRequestWithSingleServiceTest()
        {
            IKsiService haService =
                new HAKsiService(
                    null,
                    null,
                    new List<IKsiService>()
                    {
                        GetPublicationsFileService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile)))
                    });

            IPublicationsFile publicationsFile = haService.GetPublicationsFile();
            Assert.AreEqual(1484438400, publicationsFile.GetLatestPublication().PublicationData.PublicationTime, "Unexpected last publication time");
        }

        /// <summary>
        /// Test publications file request with multiple sub-service.
        /// </summary>
        [Test]
        public void HAPublicationsFileRequestTest()
        {
            IKsiService haService =
                new HAKsiService(
                    null,
                    null,
                    new List<IKsiService>()
                    {
                        GetPublicationsFileService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile))),
                        GetPublicationsFileService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile)))
                    });

            IPublicationsFile publicationsFile = haService.GetPublicationsFile();
            Assert.IsNotNull(publicationsFile, "Publications file cannot be null.");
        }

        /// <summary>
        /// Test publications file request with all sub-requests failing.
        /// </summary>
        [Test]
        public void HAPublicationsFileRequestFailTest()
        {
            IKsiService haService =
                new HAKsiService(
                    null,
                    null,
                    new List<IKsiService>()
                    {
                        GetPublicationsFileService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637))),
                        GetPublicationsFileService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637))),
                        GetPublicationsFileService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)))
                    });

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.GetPublicationsFile();
            });

            Assert.That(ex.Message.StartsWith("All sub-requests failed"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test publications file request with invalid async result.
        /// </summary>
        [Test]
        public void HAPublicationsFileRequestWithInvalidAsyncResultFailTest()
        {
            IKsiService haService =
                new HAKsiService(
                    null,
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455)
                    },
                    null);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                IAsyncResult ar = haService.BeginExtend(1455494400, null, null);
                // send extending async result to publications file request ending
                haService.EndGetPublicationsFile(ar);
            });

            Assert.That(ex.Message.StartsWith("Invalid async result. Containing invalid request runner"), "Unexpected exception message: " + ex.Message);
        }

        public IKsiService GetPublicationsFileService(byte[] requestResult)
        {
            return new TestKsiService(
                null, null, null, null,
                new TestKsiServiceProtocol { RequestResult = requestResult, UseRequestResultAsPublicationsFileResponse = true },
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))), 0, PduVersion.v1);
        }
    }
}