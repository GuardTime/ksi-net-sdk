/*
 * Copyright 2013-2016 Guardtime, Inc.
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

using System.IO;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Trust;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    /// <summary>
    /// Aggregator configuration tests with static response
    /// </summary>
    [TestFixture]
    public class AggregatorConfigRequestStaticTests
    {
        /// <summary>
        /// Test aggregator configuration request
        /// </summary>
        [Test]
        public void AggregatorConfigRequestStaticTest()
        {
            Ksi ksi = GetKsi(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregatorConfigResponsePdu)));

            AggregatorConfig config = ksi.GetAggregatorConfig();

            Assert.AreEqual(17, config.MaxLevel, "Unexpected max level value");
            Assert.AreEqual(1, config.AggregationAlgorithm, "Unexpected algorithm value");
            Assert.AreEqual(400, config.AggregationPeriod, "Unexpected aggregation period value");
            Assert.AreEqual(1024, config.MaxRequests, "Unexpected max requests value");
        }

        /// <summary>
        /// Test aggregator configuration request
        /// </summary>
        [Test]
        public void AggregatorConfigRequestWithMultiPayloadsResponseStaticTest()
        {
            // Response has multiple payloads (including a payload containing invalid signature and a configuration payload)
            Ksi ksi = GetKsi(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_Multi_Payloads)));

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
            Ksi ksi = GetKsi(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu)));

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.GetAggregatorConfig();
            });

            Assert.That(ex.Message.StartsWith("Invalid aggregator config response PDU. Could not find a valid payload."), "Unexpected exception message: " + ex.Message);
        }

        private static Ksi GetKsi(byte[] requestResult)
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol
            {
                RequestResult = requestResult
            };

            return new Ksi(new TestKsiService(protocol, new ServiceCredentials("anon", "anon"), protocol, new ServiceCredentials("anon", "anon"), protocol,
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))), 0, PduVersion.v2));
        }
    }
}