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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;
using Guardtime.KSI.Service.HighAvailability;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service.HighAvailability
{
    /// <summary>
    /// High availability extending tests with static response
    /// </summary>
    [TestFixture]
    public class HAExtendingStaticTests : StaticServiceTestsBase
    {
        /// <summary>
        /// Test extending with single sub-service
        /// </summary>
        [Test]
        public void HAExtendingWithSingleServiceTest()
        {
            IKsiService haService =
                new HAKsiService(
                    null,
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455)
                    },
                    null);

            CalendarHashChain cal = haService.Extend(123);

            Assert.AreEqual(1455478441, cal.AggregationTime, "Unexpected aggregation time.");
            Assert.AreEqual(1455494400, cal.PublicationTime, "Unexpected publication time.");
        }

        /// <summary>
        /// Test extending without extending services.
        /// </summary>
        [Test]
        public void HAExtedWithoutServicesFailTest()
        {
            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1),
                    },
                    null,
                    GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1)
                );

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.Extend(123);
            });

            Assert.That(ex.Message.StartsWith("Sub-services are missing"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test extending with multiple sub-service.
        /// </summary>
        [Test]
        public void HAExtendWithMultipleServicesTest()
        {
            IKsiService haService =
                new HAKsiService(
                    null,
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101454)), 1043101455),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101454)), 1043101455)
                    },
                    null);

            Assert.AreEqual("test.extender.address; test.extender.address; test.extender.address; ", haService.ExtenderAddress, "Unexpected extender address.");
            CalendarHashChain cal = haService.Extend(123);
            Assert.AreEqual(1455478441, cal.AggregationTime, "Unexpected aggregation time.");
            Assert.AreEqual(1455494400, cal.PublicationTime, "Unexpected publication time.");
        }

        /// <summary>
        /// Test with 4 sub-services. Max 3 is allowed.
        /// </summary>
        [Test]
        public void HACreateServiceWith4SubServicesFailTest()
        {
            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                IKsiService haService =
                    new HAKsiService(
                        null,
                        new List<IKsiService>()
                        {
                            GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1),
                            GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 2),
                            GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455),
                            GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455)
                        },
                        null);
            });

            Assert.That(ex.Message.StartsWith("Cannot use more than 3 extending services"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test aing with all sub-requests failing.
        /// </summary>
        [Test]
        public void HAExtendAllServicesFailTest()
        {
            IKsiService haService =
                new HAKsiService(
                    null,
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 2),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637),
                    },
                    null);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.Extend(123);
            });

            Assert.That(ex.Message.StartsWith("All sub-requests failed"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test extending with invalid async result.
        /// </summary>
        [Test]
        public void HAExtendWithInvalidAsyncResultFailTest()
        {
            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637),
                    },
                    null,
                    null);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                IAsyncResult ar = haService.BeginSign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")), null, null);
                // send signing async result to extend ending
                haService.EndExtend(ar);
            });

            Assert.That(ex.Message.StartsWith("Invalid async result. Containing invalid request runner"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test extending with invalid TLV in result list.
        /// </summary>
        [Test]
        public void HAExtendWithInvalidResultTlvFailTest()
        {
            IKsiService haService =
                new HAKsiService(
                    null,
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtenderConfigResponsePdu)), 1043101455)
                    },
                    null);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                HAAsyncResult ar = (HAAsyncResult)haService.BeginExtend(1455494400, null, null);
                // add invalid result
                ar.AddResultTlv(new IntegerTag(1, false, false, 1));
                haService.EndExtend(ar);
            });

            Assert.That(ex.Message.StartsWith("Could not get request response of type " + typeof(CalendarHashChain)), "Unexpected exception message: " + ex.Message);
        }
    }
}