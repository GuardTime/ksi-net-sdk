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
    /// Aggregator configuration tests with static response
    /// </summary>
    [TestFixture]
    public class AggregatorConfigRequestStaticTests : StaticServiceTestsBase
    {
        [Test]
        public void BeginGetAggregatorConfigWithoutSigningServiceProtocol()
        {
            KsiService service = new KsiService(null, null, null, null, null, null);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.BeginGetAggregatorConfig(null, null);
            });

            Assert.That(ex.Message.StartsWith("Signing service protocol is missing from service"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void BeginGetAggregatorConfigWithoutSigningServiceCredentials()
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol();
            KsiService service = new KsiService(protocol, null, null, null, null, null);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.BeginGetAggregatorConfig(null, null);
            });

            Assert.That(ex.Message.StartsWith("Signing service credentials are missing."), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void EndGetAggregatorConfigWithoutSigningServiceProtocol()
        {
            KsiService service = new KsiService(null, null, null, null, null, null);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.EndGetAggregatorConfig(new TestAsyncResult());
            });

            Assert.That(ex.Message.StartsWith("Signing service protocol is missing from service"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test aggregator configuration request
        /// </summary>
        [Test]
        public void AggregatorConfigRequestStaticTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregatorConfigResponsePdu);

            AggregatorConfig config = ksi.GetAggregatorConfig();

            Assert.AreEqual(17, config.MaxLevel, "Unexpected max level value");
            Assert.AreEqual(1, config.AggregationAlgorithm, "Unexpected algorithm value");
            Assert.AreEqual(400, config.AggregationPeriod, "Unexpected aggregation period value");
            Assert.AreEqual(1024, config.MaxRequests, "Unexpected max requests value");
        }

        /// <summary>
        /// Test aggregator configuration request. Response PDU contains multiple payloads. Warning about unexpected payload is logged.
        /// </summary>
        [Test]
        public void AggregatorConfigRequestWithMultiPayloadsResponseStaticTest()
        {
            // Response has multiple payloads (2 signature payloads and a configuration payload)
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_Multi_Payloads);

            AggregatorConfig config = ksi.GetAggregatorConfig();

            Assert.AreEqual(17, config.MaxLevel, "Unexpected max level value");
            Assert.AreEqual(1, config.AggregationAlgorithm, "Unexpected algorithm value");
            Assert.AreEqual(400, config.AggregationPeriod, "Unexpected aggregation period value");
            Assert.AreEqual(1024, config.MaxRequests, "Unexpected max requests value");
        }

        /// <summary>
        /// Test aggregator configuration request. Response PDU contains acknowledgment.
        /// </summary>
        [Test]
        public void AggregatorConfigRequestWithAcknowledgmentStaticTest()
        {
            // Response has multiple payloads (a configuration payload and an acknowledgment payload)
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregatorConfigResponsePdu_With_Acknowledgment);

            AggregatorConfig config = ksi.GetAggregatorConfig();

            Assert.AreEqual(17, config.MaxLevel, "Unexpected max level value");
            Assert.AreEqual(1, config.AggregationAlgorithm, "Unexpected algorithm value");
            Assert.AreEqual(400, config.AggregationPeriod, "Unexpected aggregation period value");
            Assert.AreEqual(1024, config.MaxRequests, "Unexpected max requests value");
        }

        /// <summary>
        /// Test aggregator configuration request fail.
        /// </summary>
        [Test]
        public void AggregatorConfigRequestInvalidStaticTest()
        {
            // pdu does not contain aggregator config payload
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_RequestId_1584727637);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.GetAggregatorConfig();
            });

            Assert.That(ex.Message.StartsWith("Invalid response PDU. Could not find a valid payload."),
                "Unexpected exception message: " + ex.Message);
        }
    }
}