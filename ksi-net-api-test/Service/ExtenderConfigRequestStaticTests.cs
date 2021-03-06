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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Service;
using Guardtime.KSI.Test.Properties;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    /// <summary>
    /// Extender configuration tests with static response
    /// </summary>
    [TestFixture]
    public class ExtenderConfigRequestStaticTests : StaticServiceTestsBase
    {
        [Test]
        public void BeginetExtenderConfigWithoutExtendingServiceProtocol()
        {
            KsiService service = new KsiService(null, null, null, null, null, null);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.BeginGetExtenderConfig(null, null);
            });

            Assert.That(ex.Message.StartsWith("Extending service protocol is missing from service"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void BeginGetExtenderConfigWithoutExtendingServiceCredentials()
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol();
            KsiService service = new KsiService(null, null, protocol, null, null, null);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.BeginGetExtenderConfig(null, null);
            });

            Assert.That(ex.Message.StartsWith("Extending service credentials are missing."), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void EndGetExtenderConfigWithoutExtendingServiceProtocol()
        {
            KsiService service = new KsiService(null, null, null, null, null, null);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.EndGetExtenderConfig(new TestAsyncResult());
            });

            Assert.That(ex.Message.StartsWith("Extending service protocol is missing from service"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test extender configuration request
        /// </summary>
        [Test]
        public void ExtenderConfigRequestStaticTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtenderConfigResponsePdu);

            ExtenderConfig config = ksi.GetExtenderConfig();

            Assert.AreEqual(273, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1455478441, config.CalendarFirstTime, "Unexpected calendar first time value");
            Assert.AreEqual(1455478442, config.CalendarLastTime, "Unexpected calendar last time value");
        }

        /// <summary>
        /// Test extender configuration request. Warning about unexpected payload is logged.
        /// </summary>
        [Test]
        public void ExtenderConfigRequestWithMultiPayloadsResponseStaticTest()
        {
            // Response has multiple payloads (2 extending payloads and a configuration payload)
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_Multi_Payloads);

            ExtenderConfig config = ksi.GetExtenderConfig();

            Assert.AreEqual(273, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1455478441, config.CalendarFirstTime, "Unexpected calendar first time value");
            Assert.AreEqual(1455478442, config.CalendarLastTime, "Unexpected calendar last time value");
        }

        /// <summary>
        /// Test extender configuration request fail.
        /// </summary>
        [Test]
        public void ExtenderConfigRequestInvalidStaticTest()
        {
            // pdu does not contain extender config payload
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.GetExtenderConfig();
            });

            Assert.That(ex.Message.StartsWith("Invalid response PDU. Could not find a valid payload."), "Unexpected exception message: " + ex.Message);
        }
    }
}