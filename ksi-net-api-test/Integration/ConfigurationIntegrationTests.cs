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

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidSigningUrl))]
        public void GetAggregatorConfigWithInvalidUrlTest(Ksi ksi)
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
                Exception ex = Assert.Throws<KsiServiceProtocolException>(delegate
                {
                    ksi.GetAggregatorConfig();
                });

                Assert.That(ex.Message.StartsWith("Request failed"), "Unexpected exception message: " + ex.Message);
                Assert.That(ex.InnerException.Message.StartsWith("The remote name could not be resolved"), "Unexpected inner exception message: " + ex.InnerException.Message);
            }
        }

        private ManualResetEvent _waitHandle;
        private AggregatorConfig _aggregatorConfig;

        [Test]
        public void GetAggregatorConfigUsingEventHandlerTest()
        {
            KsiService service = GetHttpKsiService();
            service.AggregatorConfigChanged += Service_AggregatorConfigChanged;
            _waitHandle = new ManualResetEvent(false);

            if (TestSetup.PduVersion == PduVersion.v1)
            {
                Exception ex = Assert.Throws<KsiServiceException>(delegate
                {
                    service.GetAggregatorConfig();
                });

                Assert.That(ex.Message.StartsWith("Aggregator config request is not supported using PDU version v1"), "Unexpected exception message: " + ex.Message);
            }
            else
            {
                service.GetAggregatorConfig();
            }

            _waitHandle.WaitOne(10000);

            Assert.IsNotNull(_aggregatorConfig, "Could not get aggregator config using event handler.");
        }

        private void Service_AggregatorConfigChanged(object sender, AggregatorConfigChangedEventArgs e)
        {
            _aggregatorConfig = e.AggregatorConfig;
            _waitHandle.Set();
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidExtendingUrl))]
        public void GetAggregatorConfigSuccessWithInvalidExtendingUrlTest(Ksi ksi)
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
        public void GetAggregatorConfigSuccessWithInvalidExtendingPassTest(Ksi ksi)
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

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidExtendingUrl))]
        public void GetExtenderConfigWithInvalidUrlTest(Ksi ksi)
        {
            if (TestSetup.PduVersion == PduVersion.v1)
            {
                Exception ex = Assert.Throws<KsiServiceException>(delegate
                {
                    ksi.GetAggregatorConfig();
                });

                Assert.That(ex.Message.StartsWith("Extender config request is not supported using PDU version v1"), "Unexpected exception message: " + ex.Message);
            }

            else
            {
                Exception ex = Assert.Throws<KsiServiceProtocolException>(delegate
                {
                    ksi.GetExtenderConfig();
                });

                Assert.That(ex.Message.StartsWith("Request failed"), "Unexpected exception message: " + ex.Message);
                Assert.That(ex.InnerException.Message.StartsWith("The remote name could not be resolved"), "Unexpected inner exception message: " + ex.InnerException.Message);
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

        private ManualResetEvent _waitHandle2;
        private ExtenderConfig _extenderConfig;

        [Test]
        public void GetExtenderrConfigUsingEventHandlerTest()
        {
            KsiService service = GetHttpKsiService();
            service.ExtenderConfigChanged += Service_ExtenderConfigChanged;
            _waitHandle2 = new ManualResetEvent(false);

            if (TestSetup.PduVersion == PduVersion.v1)
            {
                Exception ex = Assert.Throws<KsiServiceException>(delegate
                {
                    service.GetExtenderConfig();
                });

                Assert.That(ex.Message.StartsWith("Extender config request is not supported using PDU version v1"), "Unexpected exception message: " + ex.Message);
            }
            else
            {
                service.GetExtenderConfig();
            }

            _waitHandle2.WaitOne(10000);

            Assert.IsNotNull(_extenderConfig, "Could not get extender config using event handler.");
        }

        private void Service_ExtenderConfigChanged(object sender, ExtenderConfigChangedEventArgs e)
        {
            _extenderConfig = e.ExtenderConfig;
            _waitHandle2.Set();
        }
    }
}