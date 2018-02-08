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
using System.Reflection;
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
    /// High availability signing tests with static response
    /// </summary>
    [TestFixture]
    public class HASigningStaticTests : StaticServiceTestsBase
    {
        /// <summary>
        /// Test signing without signing services.
        /// </summary>
        [Test]
        public void HASignWithoutServicesFailTest()
        {
            IKsiService haService =
                new HAKsiService(
                    null,
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1),
                    },
                    GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1));

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.Sign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
            });

            Assert.That(ex.Message.StartsWith("Sub-services are missing"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing with single sub-service
        /// </summary>
        [Test]
        public void HASignWithSingleServiceTest()
        {
            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637)
                    },
                    null, null);

            DataHash inputHash = new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            IKsiSignature signature = haService.Sign(inputHash);

            Assert.AreEqual(inputHash, signature.InputHash, "Unexpected signature input hash.");
        }

        /// <summary>
        /// Test signing with multiple sub-service.
        /// </summary>
        [Test]
        public void HASignWithMutlipleServicesTest()
        {
            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727638),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637)
                    },
                    null, null);

            Assert.AreEqual("test.aggregator.address; test.aggregator.address; test.aggregator.address; ", haService.AggregatorAddress, "Unexpected aggregator address.");
            IKsiSignature signature = haService.Sign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
            Assert.IsNotNull(signature, "Signature cannot be null.");
        }

        /// <summary>
        /// Test get sign response payload
        /// </summary>
        [Test]
        public void HASignWithPayloadResponseTest()
        {
            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727638),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637)
                    },
                    null, null);

            IAsyncResult ar = haService.BeginSign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")), null, null);
            SignRequestResponsePayload payload = haService.GetSignResponsePayload(ar);
            Assert.IsNotNull(payload, "Sign request response payload cannot be null.");
        }

        /// <summary>
        /// Test get sign response payload. 1 sec delay is added between request begin and end.
        /// </summary>
        [Test]
        public void HASignWithPayloadResponseAndWaitTest()
        {
            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727638),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637)
                    },
                    null, null);

            IAsyncResult ar = haService.BeginSign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")), null, null);
            SignRequestResponsePayload payload = haService.GetSignResponsePayload(ar);
            Assert.IsNotNull(payload, "Sign request response payload cannot be null.");
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
                        new List<IKsiService>()
                        {
                            GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1),
                            GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 2),
                            GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1043101455),
                            GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1043101455)
                        },
                        null, null);
            });

            Assert.That(ex.Message.StartsWith("Cannot use more than 3 signing services"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing with all sub-requests failing.
        /// </summary>
        [Test]
        public void HASignAllServicesFailTest()
        {
            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 2),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455)
                    },
                    null, null);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.Sign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
            });

            Assert.That(ex.Message.StartsWith("All sub-requests failed"), "Unexpected exception message: " + ex.Message);
            Assert.AreEqual(3, ex.SubServiceExceptions.Count, "Unexpected sub-service exception count");
            Assert.That(ex.SubServiceExceptions[0].Message.StartsWith("Using sub-service failed"),
                "Unexpected sub-service exception message: " + ex.SubServiceExceptions[0].Message);
        }

        /// <summary>
        /// Test signing with invalid async result.
        /// </summary>
        [Test]
        public void HASignWithInvalidAsyncResultFailTest()
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
                // send extending async result to sign ending
                haService.EndSign(ar);
            });

            Assert.That(ex.Message.StartsWith("Invalid async result. Containing invalid request runner"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test getting sign response payload with invalid async result.
        /// </summary>
        [Test]
        public void HAGetSignResponsePayloadWithInvalidAsyncResultFailTest()
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
                // use extending async result
                haService.GetSignResponsePayload(ar);
            });

            Assert.That(ex.Message.StartsWith("Invalid async result. Containing invalid request runner"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing with async result null.
        /// </summary>
        [Test]
        public void HASignWithAsyncResultNullFailTest()
        {
            IKsiService haService =
                new HAKsiService(
                    null,
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455)
                    },
                    null);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                haService.EndSign(null);
            });

            Assert.AreEqual("asyncResult", ex.ParamName, "Unexpected exception: " + ex.Message);
        }

        /// <summary>
        /// Test signing with invalid type of async result.
        /// </summary>
        [Test]
        public void HASignWithInvalidTypeAsyncResultFailTest()
        {
            IKsiService haService = new HAKsiService(null, null, null);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                IAsyncResult ar = GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)),
                    1584727637).BeginSign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")), null, null);
                haService.EndSign(ar);
            });
            Assert.That(ex.Message.StartsWith("Invalid asyncResult, could not cast to correct object"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing with invalid TLV in result list.
        /// </summary>
        [Test]
        public void HASignWithInvalidResultTlvFailTest()
        {
            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregatorConfigResponsePdu)),
                            1584727637)
                    },
                    null, null);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                HAAsyncResult asyncResult = (HAAsyncResult)haService.BeginSign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")),
                    null, null);

                // add invalid result
                FieldInfo memberInfo = typeof(HARequestRunner).GetField("_resultTlvs", BindingFlags.NonPublic | BindingFlags.Instance);
                List<object> results = (List<object>)memberInfo.GetValue(asyncResult.RequestRunner);
                results.Add(new IntegerTag(1, false, false, 1));

                haService.EndSign(asyncResult);
            });

            Assert.That(ex.Message.StartsWith("Could not get request response of type " + typeof(KsiSignature)), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test HA sign request timeout.
        /// </summary>
        [Test]
        public void HASignTimeoutTest()
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol
            {
                RequestResult = File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)),
                DelayMilliseconds = 3000
            };

            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(protocol, 1584727637),
                    },
                    null, null, 1000);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.Sign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
            });

            Assert.That(ex.Message.StartsWith("HA service request timed out"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test HA sign request timeout. One sub-services delays, but the other is succeeds.
        /// </summary>
        [Test]
        public void HASignWithOneSubServiceTimeoutTest()
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol
            {
                RequestResult = File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)),
                DelayMilliseconds = 3000
            };

            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(protocol, 1584727637),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637)
                    },
                    null, null, 1000);

            haService.Sign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
        }
    }
}