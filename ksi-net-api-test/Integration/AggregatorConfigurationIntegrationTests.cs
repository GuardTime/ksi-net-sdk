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
    public class AggregatorConfigurationIntegrationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiList))]
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

        /// <summary>
        /// Test getting aggregator config while extending service pass is invalid which should not prevent getting aggregator config.
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiListWithInvalidExtendingPass))]
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

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServices))]
        public void AsyncGetAggregatorConfigTest(KsiService service)
        {
            if (TestSetup.PduVersion == PduVersion.v1)
            {
                return;
            }

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

        private ManualResetEvent _waitHandle;
        private AggregatorConfig _aggregatorConfig;

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(GetKsiServices))]
        public void GetAggregatorConfigUsingEventHandlerTest(KsiService service)
        {
            service.AggregatorConfigChanged += Service_AggregatorConfigChanged;
            _waitHandle = new ManualResetEvent(false);
            _aggregatorConfig = null;

            if (TestSetup.PduVersion == PduVersion.v1)
            {
                Exception ex = Assert.Throws<KsiServiceException>(delegate
                {
                    service.GetAggregatorConfig();
                });

                Assert.That(ex.Message.StartsWith("Aggregator config request is not supported using PDU version v1"), "Unexpected exception message: " + ex.Message);
                return;
            }

            service.GetAggregatorConfig();
            _waitHandle.WaitOne(10000);
            Assert.IsNotNull(_aggregatorConfig, "Could not get aggregator config using event handler.");
        }

        private void Service_AggregatorConfigChanged(object sender, AggregatorConfigChangedEventArgs e)
        {
            _aggregatorConfig = e.AggregatorConfig;
            _waitHandle.Set();
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsiWithInvalidSigningUrl))]
        public void HttpGetAggregatorConfigWithInvalidUrlTest(Ksi ksi)
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

        /// <summary>
        /// Test getting aggregator config via HTTP while extending service url is invalid which should not getting aggregator config.
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsiWithInvalidExtendingUrl))]
        public void HttpGetAggregatorConfigSuccessWithInvalidExtendingUrlTest(Ksi ksi)
        {
            if (TestSetup.PduVersion != PduVersion.v1)
            {
                Assert.DoesNotThrow(delegate
                {
                    ksi.GetAggregatorConfig();
                }, "Invalid extending url should not prevent getting aggregator config.");
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpKsiWithInvalidSigningPort))]
        public void TcpGetAggregatorConfigWithInvalidPortTest(Ksi ksi)
        {
            Exception ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                ksi.GetAggregatorConfig();
            });
            Assert.That(ex.Message.StartsWith("Completing connection failed"), "Unexpected exception message: " + ex.Message);
            Assert.IsNotNull(ex.InnerException, "Inner exception should not be null");
            Assert.That(ex.InnerException.Message.StartsWith("No connection could be made because the target machine actively refused it"),
                "Unexpected inner exception message: " + ex.InnerException.Message);
        }

        /// <summary>
        /// Test getting aggregator config via TCP while extending service port is invalid which should not prevent getting aggregator config.
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpKsiWithInvalidExtendingPort))]
        public void TcpGetAggregatorConfigSuccessWithInvalidExtendingPortTest(Ksi ksi)
        {
            Assert.DoesNotThrow(delegate
            {
                ksi.GetAggregatorConfig();
            }, "Invalid exteding port should not prevent signing.");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpKsiWithInvalidExtendingPort))]
        public void TcpGetAggregatorConfigWithInvalidExtendingPortTest(Ksi ksi)
        {
            Assert.DoesNotThrow(delegate
            {
                ksi.GetAggregatorConfig();
            }, "Invalid exteding port should not prevent signing.");
        }
    }
}