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
    public class ExtenderConfigurationIntegrationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiList))]
        public void GetExtenderConfigTest(Ksi ksi)
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

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiListWithInvalidSigningPass))]
        public void GetExtenderConfigSuccessWithInvalidSigningPassTest(Ksi ksi)
        {
            if (TestSetup.PduVersion != PduVersion.v1)
            {
                Assert.DoesNotThrow(delegate
                {
                    ksi.GetExtenderConfig();
                }, "Invalid signing password should not prevent getting extender config.");
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServices))]
        public void AsyncGetExtenderConfigTest(KsiService service)
        {
            if (TestSetup.PduVersion == PduVersion.v1)
            {
                return;
            }

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

        private ManualResetEvent _waitHandle;
        private ExtenderConfig _extenderConfig;

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(GetKsiServices))]
        public void GetExtenderrConfigUsingEventHandlerTest(KsiService service)
        {
            service.ExtenderConfigChanged += Service_ExtenderConfigChanged;
            _waitHandle = new ManualResetEvent(false);

            if (TestSetup.PduVersion == PduVersion.v1)
            {
                Exception ex = Assert.Throws<KsiServiceException>(delegate
                {
                    service.GetExtenderConfig();
                });

                Assert.That(ex.Message.StartsWith("Extender config request is not supported using PDU version v1"), "Unexpected exception message: " + ex.Message);
                return;
            }

            service.GetExtenderConfig();
            _waitHandle.WaitOne(10000);
            Assert.IsNotNull(_extenderConfig, "Could not get extender config using event handler.");
        }

        private void Service_ExtenderConfigChanged(object sender, ExtenderConfigChangedEventArgs e)
        {
            _extenderConfig = e.ExtenderConfig;
            _waitHandle.Set();
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsiWithInvalidExtendingUrl))]
        public void HttpGetExtenderConfigSuccessWithInvalidUrlTest(Ksi ksi)
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
                Exception ex = Assert.Throws<KsiServiceProtocolException>(delegate
                {
                    ksi.GetExtenderConfig();
                });

                Assert.That(ex.Message.StartsWith("Request failed"), "Unexpected exception message: " + ex.Message);
                Assert.That(ex.InnerException.Message.StartsWith("The remote name could not be resolved"), "Unexpected inner exception message: " + ex.InnerException.Message);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsiWithInvalidSigningUrl))]
        public void HttpGetExtenderConfigSuccessWithInvalidSigningUrlTest(Ksi ksi)
        {
            if (TestSetup.PduVersion != PduVersion.v1)
            {
                Assert.DoesNotThrow(delegate
                {
                    ksi.GetExtenderConfig();
                }, "Invalid signing url should not prevent getting extender config.");
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpKsiWithInvalidExtendingPort))]
        public void TcpGetExtenderConfigWithInvalidPortTest(Ksi ksi)
        {
            Exception ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                ksi.GetExtenderConfig();
            });
            Assert.That(ex.Message.StartsWith("Completing connection failed"), "Unexpected exception message: " + ex.Message);
            Assert.IsNotNull(ex.InnerException, "Inner exception should not be null");
            Assert.That(ex.InnerException.Message.StartsWith("No connection could be made because the target machine actively refused it"),
                "Unexpected inner exception message: " + ex.InnerException.Message);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpKsiWithInvalidSigningPort))]
        public void TcpGetExtenderConfigWithInvalidSigningPortTest(Ksi ksi)
        {
            Assert.DoesNotThrow(delegate
            {
                ksi.GetExtenderConfig();
            }, "Invalid signing port should not prevent signing.");
        }
    }
}