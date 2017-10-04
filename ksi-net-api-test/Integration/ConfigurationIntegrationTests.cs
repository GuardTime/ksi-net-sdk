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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Service;
using NUnit.Framework;
using System;
using System.Threading;

namespace Guardtime.KSI.Test.Integration
{
    [TestFixture]
    public class ConfigurationIntegrationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void GetAggregatorConfigTest(Ksi ksi)
        {
            if (TestSetup.PduVersion == PduVersion.v1)
            {
                Exception ex = Assert.Throws<KsiServiceException>(delegate
                {
                    ksi.GetAggregatorConfig();
                });

                Assert.That(ex.Message.StartsWith("Aggregator config request is not supported using PDU version v1"), "Unexpected exception message: " + ex.Message);
            }
            else
            {
                ksi.GetAggregatorConfig();
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void GetAggregatorConfigTcpTest(Ksi ksi)
        {
            KsiService service = GetTcpKsiService();

            if (TestSetup.PduVersion == PduVersion.v1)
            {
                Exception ex = Assert.Throws<KsiServiceException>(delegate
                {
                    service.BeginGetAggregatorConfig(null, null);
                });

                Assert.That(ex.Message.StartsWith("Aggregator config request is not supported using PDU version v1"), "Unexpected exception message: " + ex.Message);
            }
            else
            {
                // test with 2 config requests
                IAsyncResult asyncResult1 = service.BeginGetAggregatorConfig(null, null);
                IAsyncResult asyncResult2 = service.BeginGetAggregatorConfig(null, null);

                AggregatorConfig conf1 = service.EndGetAggregatorConfig(asyncResult1);
                AggregatorConfig conf2 = service.EndGetAggregatorConfig(asyncResult2);

                Assert.AreEqual(conf1.AggregationAlgorithm, conf2.AggregationAlgorithm);
                Assert.AreEqual(conf1.AggregationPeriod, conf2.AggregationPeriod);
                Assert.AreEqual(conf1.MaxLevel, conf2.MaxLevel);
                Assert.AreEqual(conf1.MaxRequests, conf2.MaxRequests);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidExtendingUrl))]
        public void GetAggregatorConfigSuccessWithInvalidSigningUrlTest(Ksi ksi)
        {
            if (TestSetup.PduVersion != PduVersion.v1)
            {
                Assert.DoesNotThrow(delegate
                {
                    ksi.GetAggregatorConfig();
                }, "Invalid extending url should not prevent getting aggregator config.");
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidExtendingPass))]
        public void GetAggregatorConfigSuccessWithInvalidSigningPassTest(Ksi ksi)
        {
            if (TestSetup.PduVersion != PduVersion.v1)
            {
                Assert.DoesNotThrow(delegate
                {
                    ksi.GetAggregatorConfig();
                }, "Invalid extending password should not prevent getting aggregator config.");
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void GetExtenderConfig(Ksi ksi)
        {
            if (TestSetup.PduVersion == PduVersion.v1)
            {
                Exception ex = Assert.Throws<KsiServiceException>(delegate
                {
                    ksi.GetExtenderConfig();
                });

                Assert.That(ex.Message.StartsWith("Extender config request is not supported using PDU version v1"), "Unexpected exception message: " + ex.Message);
            }
            else
            {
                ksi.GetExtenderConfig();
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidSigningUrl))]
        public void GetExtenderConfigSuccessWithInvalidSigningUrlTest(Ksi ksi)
        {
            if (TestSetup.PduVersion != PduVersion.v1)
            {
                Assert.DoesNotThrow(delegate
                {
                    ksi.GetExtenderConfig();
                }, "Invalid signing url should not prevent getting extnder config.");
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidSigningPass))]
        public void GetExtenderConfigSuccessWithInvalidSigningPassTest(Ksi ksi)
        {
            if (TestSetup.PduVersion != PduVersion.v1)
            {
                Assert.DoesNotThrow(delegate
                {
                    ksi.GetExtenderConfig();
                }, "Invalid signing password should not prevent getting extnder config.");
            }
        }

        [Test]
        public void HttpAsyncGetAggregatorConfigTest()
        {
            if (TestSetup.PduVersion == PduVersion.v1)
            {
                return;
            }

            KsiService service = GetHttpKsiService();
            ManualResetEvent waitHandle = new ManualResetEvent(false);
            AggregatorConfig config = null;
            object testObject = new object();
            bool isAsyncCorrect = false;

            service.BeginGetAggregatorConfig(delegate(IAsyncResult ar)
            {
                try
                {
                    isAsyncCorrect = ar.AsyncState == testObject;
                    config = service.EndGetAggregatorConfig(ar);
                }
                finally
                {
                    waitHandle.Set();
                }
            }, testObject);

            waitHandle.WaitOne();

            Assert.IsNotNull(config, "Aggregator configuration should not be null.");
            Assert.AreEqual(true, isAsyncCorrect, "Unexpected async state.");
        }

        [Test]
        public void HttpAsyncGetExtenderConfigTest()
        {
            if (TestSetup.PduVersion == PduVersion.v1)
            {
                return;
            }

            KsiService service = GetHttpKsiService();
            ManualResetEvent waitHandle = new ManualResetEvent(false);
            ExtenderConfig config = null;
            object testObject = new object();
            bool isAsyncCorrect = false;

            service.BeginGetExtenderConfig(delegate(IAsyncResult ar)
            {
                try
                {
                    isAsyncCorrect = ar.AsyncState == testObject;
                    config = service.EndGetExtenderConfig(ar);
                }
                finally
                {
                    waitHandle.Set();
                }
            }, testObject);

            waitHandle.WaitOne();

            Assert.IsNotNull(config, "Extender configuration should not be null.");
            Assert.AreEqual(true, isAsyncCorrect, "Unexpected async state.");
        }
    }
}