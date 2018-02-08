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

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
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
    [TestFixture]
    public class HAAggregatorConfigStaticTests : StaticServiceTestsBase
    {
        [Test]
        public void HAAggregatorConfigRequestWithSingleServiceTest()
        {
            // Test getting aggregator configuration with single sub-service
            IKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(1, 2, 100, 4, new List<string>() { "uri-1" })
                });

            haService.GetAggregatorConfig();

            AggregatorConfig config = haService.GetAggregatorConfig();

            Assert.AreEqual(1, config.MaxLevel, "Unexpected max level value");
            Assert.AreEqual(2, config.AggregationAlgorithm, "Unexpected algorithm value");
            Assert.AreEqual(100, config.AggregationPeriod, "Unexpected aggregation period value");
            Assert.AreEqual(4, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, config.ParentsUris.Count, "Unexpected parent uri count");
            Assert.AreEqual("uri-1", config.ParentsUris[0], "Unexpected parent uri value at position 0");
        }

        [Test]
        public void HAAggregatorConfigRequestTest()
        {
            // Test getting aggregator configuration with 1 successful and 2 unsuccessful sub-service responses 

            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727638),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregatorConfigResponsePdu)), 1584727637),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637)
                    },
                    null, null);

            AggregatorConfig config = haService.GetAggregatorConfig();

            Assert.AreEqual(17, config.MaxLevel, "Unexpected max level value");
            Assert.AreEqual(1, config.AggregationAlgorithm, "Unexpected algorithm value");
            Assert.AreEqual(400, config.AggregationPeriod, "Unexpected aggregation period value");
            Assert.AreEqual(1024, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(0, config.ParentsUris.Count, "Unexpected parent uri count");
        }

        [Test]
        public void HAAggregatorConfigRequestUsingEventHandlerTest()
        {
            // Test getting aggregator configuration with 1 successful and 2 unsuccessful sub-service responses. 
            // Get response using AggregatorConfigChanged event handler

            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727638),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregatorConfigResponsePdu)), 1584727637),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637)
                    },
                    null, null);

            ManualResetEvent waitHandle = new ManualResetEvent(false);
            AggregatorConfig aggregatorConfig = null;

            haService.AggregatorConfigChanged += delegate(object sender, AggregatorConfigChangedEventArgs e)
            {
                aggregatorConfig = e.AggregatorConfig;
                waitHandle.Set();
            };
            haService.GetAggregatorConfig();
            waitHandle.WaitOne(1000);
            Assert.IsNotNull(aggregatorConfig, "Could not get aggregator config using event handler.");

            Assert.AreEqual(17, aggregatorConfig.MaxLevel, "Unexpected max level value");
            Assert.AreEqual(1, aggregatorConfig.AggregationAlgorithm, "Unexpected algorithm value");
            Assert.AreEqual(400, aggregatorConfig.AggregationPeriod, "Unexpected aggregation period value");
            Assert.AreEqual(1024, aggregatorConfig.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(0, aggregatorConfig.ParentsUris.Count, "Unexpected parent uri count");
        }

        [Test]
        public void HAAggregatorConfigRequestFailSTest()
        {
            // Test getting aggregator configuration with all 3 sub-services responses failing

            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 2),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 3)
                    },
                    null, null);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.GetAggregatorConfig();
            });

            Assert.That(ex.Message.StartsWith("Could not get aggregator configuration"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void HAGetConfigSingleResultAllNullsTest()
        {
            // Test getting aggregator configuration with 1 successful sub-service response
            // All the values are empty

            IKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(null, null, null, null, null),
                });

            AggregatorConfig config = haService.GetAggregatorConfig();

            Assert.IsNull(config.MaxLevel, "Unexpected max level value");
            Assert.IsNull(config.AggregationAlgorithm, "Unexpected algorithm value");
            Assert.IsNull(config.AggregationPeriod, "Unexpected aggregation period value");
            Assert.IsNull(config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(0, config.ParentsUris.Count, "Unexpected parent uri list");
        }

        [Test]
        public void HAGetConfigTwoResultsTest1()
        {
            // Test getting aggregator configuration with 2 successful sub-service responses

            IKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(1, 2, 100, 4, null),
                },
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(2, null, 200, 5, new List<string>() { "uri-2" })
                });

            AggregatorConfig config = haService.GetAggregatorConfig();

            Assert.AreEqual(2, config.MaxLevel, "Unexpected max level value");
            Assert.AreEqual(2, config.AggregationAlgorithm, "Unexpected algorithm value");
            Assert.AreEqual(100, config.AggregationPeriod, "Unexpected aggregation period value");
            Assert.AreEqual(5, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, config.ParentsUris.Count, "Unexpected parent uri count");
            Assert.AreEqual("uri-2", config.ParentsUris[0], "Unexpected parent uri value at position 0");
        }

        [Test]
        public void HAGetConfigTwoResultsTest2()
        {
            // Test getting aggregator configuration with 2 successful sub-service responses

            IKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(2, 3, 200, 5, new List<string>() { "uri-1" }),
                },
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(1, 2, 100, 4, new List<string>() { "uri-2" })
                });

            AggregatorConfig config = haService.GetAggregatorConfig();

            Assert.AreEqual(2, config.MaxLevel, "Unexpected max level value");
            Assert.IsTrue(config.AggregationAlgorithm == 3 || config.AggregationAlgorithm == 2, "Unexpected algorithm value");
            Assert.AreEqual(100, config.AggregationPeriod, "Unexpected aggregation period value");
            Assert.AreEqual(5, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, config.ParentsUris.Count, "Unexpected parent uri count");
            Assert.IsTrue(config.ParentsUris[0] == "uri-1" || config.ParentsUris[0] == "uri-2", "Unexpected parent uri value at position 0");
        }

        [Test]
        public void HAGetConfigTwoResultsTest3()
        {
            // Test getting aggregator configuration with 2 successful sub-service responses

            IKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(null, null, null, null, null),
                },
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(1, 2, 100, 4, new List<string>() { "uri-2" })
                });

            AggregatorConfig config = haService.GetAggregatorConfig();
            Assert.AreEqual(1, config.MaxLevel, "Unexpected max level value");
            Assert.AreEqual(2, config.AggregationAlgorithm, "Unexpected algorithm value");
            Assert.AreEqual(100, config.AggregationPeriod, "Unexpected aggregation period value");
            Assert.AreEqual(4, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, config.ParentsUris.Count, "Unexpected parent uri count");
            Assert.AreEqual("uri-2", config.ParentsUris[0], "Unexpected parent uri value at position 0");
        }

        [Test]
        public void HAGetConfigTwoResultsTest4()
        {
            // Test getting aggregator configuration with 2 successful sub-service responses

            IKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(1, 2, 100, 4, new List<string>() { "uri-1" }),
                },
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(null, null, null, null, null)
                });

            AggregatorConfig config = haService.GetAggregatorConfig();

            Assert.AreEqual(1, config.MaxLevel, "Unexpected max level value");
            Assert.AreEqual(2, config.AggregationAlgorithm, "Unexpected algorithm value");
            Assert.AreEqual(100, config.AggregationPeriod, "Unexpected aggregation period value");
            Assert.AreEqual(4, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, config.ParentsUris.Count, "Unexpected parent uri count");
            Assert.AreEqual("uri-1", config.ParentsUris[0], "Unexpected parent uri value at position 0");
        }

        [Test]
        public void HAGetConfigResultsOutOfLimitTest()
        {
            // Test getting aggregator configuration with 2 successful sub-service responses
            // Some values are out of bounds

            IKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(1, 2, 99, 4, new List<string>() { "uri-1" })
                },
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(21, null, 20001, 16001, null)
                });

            AggregatorConfig config = haService.GetAggregatorConfig();

            Assert.AreEqual(1, config.MaxLevel, "Unexpected max level value");
            Assert.AreEqual(2, config.AggregationAlgorithm, "Unexpected algorithm value");
            Assert.IsNull(config.AggregationPeriod, "Unexpected aggregation period value");
            Assert.AreEqual(4, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, config.ParentsUris.Count, "Unexpected parent uri count");
            Assert.AreEqual("uri-1", config.ParentsUris[0], "Unexpected parent uri value at position 0");
        }

        [Test]
        public void HAGetConfigResultsAndRemoveAllTest()
        {
            // A configuration request with 2 successful sub-requests is made.
            // Then a new configuration request is made with 2 unsuccessful sub-requests. 
            // Both configuration are removed from cache.
            // AggregationConfigChanged event handler should get result containing an exception.

            HAKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(1, 1, 100, 4, new List<string>() { "uri-1" })
                },
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(1, 2, 100, 4, new List<string>() { "uri-2" })
                });

            haService.GetAggregatorConfig();

            // change first service response so that request fails
            ((TestKsiService)haService.SigningServices[0]).SigningServiceProtocol.RequestResult =
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637));

            // change second service response so that request fails
            ((TestKsiService)haService.SigningServices[1]).SigningServiceProtocol.RequestResult =
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637));

            AggregatorConfigChangedEventArgs args = null;
            ManualResetEvent waitHandle = new ManualResetEvent(false);

            haService.AggregatorConfigChanged += delegate(object sender, AggregatorConfigChangedEventArgs e)
            {
                args = e;
                waitHandle.Set();
            };

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.GetAggregatorConfig();
            });

            Assert.That(ex.Message.StartsWith("Could not get aggregator configuration"), "Unexpected exception message: " + ex.Message);

            waitHandle.WaitOne(1000);

            Assert.IsNotNull(args, "AggregatorConfigChangedEventArgs cannot be null.");
            Assert.IsNull(args.AggregatorConfig, "AggregatorConfigChangedEventArgs.AggregatorConfig cannot have value.");
            Assert.IsNotNull(args.Exception, "AggregatorConfigChangedEventArgs.Exception cannot be null.");
            Assert.AreEqual(haService, args.KsiService, "Unexpected AggregatorConfigChangedEventArgs.KsiService");
            Assert.That(args.Exception.Message.StartsWith("Could not get aggregator configuration"), "Unexpected exception message: " + args.Exception.Message);
        }

        [Test]
        public void HAGetConfigResultsAndRemoveOneTest()
        {
            // A configuration request with 2 successful sub-requests is made.
            // Then a new configuration request is made with 1 successful and 1 unsuccessful sub-requests. 
            // Unsuccessful service config should be removed from cache and merged config should be recalculated

            HAKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(2, 1, 100, 4, new List<string>() { "uri-1" })
                },
                new List<PduPayload>()
                {
                    GetAggregatorConfigResponsePayload(1, 2, 100, 4, new List<string>() { "uri-2" })
                });

            ManualResetEvent waitHandle = new ManualResetEvent(false);

            haService.AggregatorConfigChanged += delegate
            {
            };

            AggregatorConfig resultConf = haService.GetAggregatorConfig();
            waitHandle.WaitOne(1000);

            Assert.AreEqual(2, resultConf.MaxLevel, "Unexpected max level value");
            Assert.AreEqual(100, resultConf.AggregationPeriod, "Unexpected aggregation period value");
            Assert.AreEqual(4, resultConf.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, resultConf.ParentsUris.Count, "Unexpected parent uri count");

            // change first service response so that request fails
            ((TestKsiService)haService.SigningServices[0]).SigningServiceProtocol.RequestResult =
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637));

            // change second service response so that a valid configuration is returned
            TestKsiService newService = (TestKsiService)GetService(new List<PduPayload>()
            {
                GetAggregationResponsePayload(Resources.KsiService_AggregationResponsePdu_RequestId_1584727638),
                GetAggregatorConfigResponsePayload(2, 3, 400, 3, new List<string>() { "uri-2-changed" })
            });

            ((TestKsiService)haService.SigningServices[1]).SigningServiceProtocol.RequestResult = newService.SigningServiceProtocol.RequestResult;

            AggregatorConfigChangedEventArgs args = null;
            waitHandle = new ManualResetEvent(false);

            haService.AggregatorConfigChanged += delegate(object sender, AggregatorConfigChangedEventArgs e)
            {
                args = e;
            };

            resultConf = haService.GetAggregatorConfig();

            Assert.AreEqual(2, resultConf.MaxLevel, "Unexpected max level value");
            Assert.AreEqual(3, resultConf.AggregationAlgorithm, "Unexpected algorithm value");
            Assert.AreEqual(400, resultConf.AggregationPeriod, "Unexpected aggregation period value");
            Assert.AreEqual(3, resultConf.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, resultConf.ParentsUris.Count, "Unexpected parent uri count");
            Assert.AreEqual("uri-2-changed", resultConf.ParentsUris[0], "Unexpected parent uri value at position 0");

            waitHandle.WaitOne(1000);

            Assert.IsNotNull(args, "AggregatorConfigChangedEventArgs cannot be null.");
            Assert.AreEqual(resultConf, args.AggregatorConfig, "Unexpected AggregatorConfigChangedEventArgs.AggregatorConfig.");
            Assert.IsNull(args.Exception, "AggregatorConfigChangedEventArgs.Exception cannot have value.");
            Assert.AreEqual(haService, args.KsiService, "Unexpected AggregatorConfigChangedEventArgs.KsiService");
        }

        [Test]
        public void HAGetConfigResultsWithSignRequestTest()
        {
            // Test getting aggregator configurations via AggregatorConfigChanged event handler when using Sign method.
            // Testing getting different configurations in a sequence

            HAKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetAggregationResponsePayload(Resources.KsiService_AggregationResponsePdu_RequestId_1584727637),
                    GetAggregatorConfigResponsePayload(1, 1, 200, 4, new List<string>() { "uri-1" })
                },
                new List<PduPayload>()
                {
                    GetAggregationResponsePayload(Resources.KsiService_AggregationResponsePdu_RequestId_1584727638),
                    GetAggregatorConfigResponsePayload(1, 1, 200, 4, new List<string>() { "uri-2" })
                });

            TestKsiService secondService = (TestKsiService)haService.SigningServices[1];
            secondService.RequestId = 1584727638;

            AggregatorConfig resultConf = null;
            int changeCount = 0;
            ManualResetEvent waitHandle = new ManualResetEvent(false);

            haService.AggregatorConfigChanged += delegate(object sender, AggregatorConfigChangedEventArgs e)
            {
                resultConf = e.AggregatorConfig;
                changeCount++;
                if (changeCount == 2)
                {
                    waitHandle.Set();
                }
            };

            DataHash inputHash = new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            IKsiSignature signature = haService.Sign(inputHash);

            Assert.AreEqual(inputHash, signature.InputHash, "Unexpected signature input hash.");
            waitHandle.WaitOne(1000);
            Assert.IsNotNull(resultConf, "Could not get aggregator config using event handler.");

            Assert.AreEqual(1, resultConf.MaxLevel, "Unexpected max level value");
            Assert.IsTrue(resultConf.AggregationAlgorithm == 1 || resultConf.AggregationAlgorithm == 2, "Unexpected algorithm value");
            Assert.AreEqual(200, resultConf.AggregationPeriod, "Unexpected aggregation period value");
            Assert.AreEqual(4, resultConf.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, resultConf.ParentsUris.Count, "Unexpected parent uri count");
            Assert.IsTrue(resultConf.ParentsUris[0] == "uri-1" || resultConf.ParentsUris[0] == "uri-2", "Unexpected parent uri value at position 0");

            // changing aggregation algorithm or parent uri should not change merged config
            TestKsiService newService = (TestKsiService)GetService(new List<PduPayload>()
            {
                GetAggregationResponsePayload(Resources.KsiService_AggregationResponsePdu_RequestId_1584727638),
                GetAggregatorConfigResponsePayload(1, 3, 200, 4, new List<string>() { "uri-2-changed" })
            });

            secondService.SigningServiceProtocol.RequestResult = newService.SigningServiceProtocol.RequestResult;

            resultConf = null;
            changeCount = 0;
            haService.Sign(inputHash);
            Thread.Sleep(1000);
            Assert.IsNull(resultConf, "Aggregator config should have not changed (2nd request)");
            Assert.AreEqual(0, changeCount, "Unexpected change count.");

            // changing max level should change merged config
            newService = (TestKsiService)GetService(new List<PduPayload>()
            {
                GetAggregationResponsePayload(Resources.KsiService_AggregationResponsePdu_RequestId_1584727638),
                GetAggregatorConfigResponsePayload(2, 2, 200, 4, new List<string>() { "uri-2", "uri-3" })
            });

            secondService.SigningServiceProtocol.RequestResult = newService.SigningServiceProtocol.RequestResult;

            waitHandle.Reset();
            resultConf = null;
            changeCount = 0;

            haService.Sign(inputHash);
            waitHandle.WaitOne(1000);
            Assert.IsNotNull(resultConf, "Could not get aggregator config using event handler (after 3rd sign request).");

            Assert.AreEqual(2, resultConf.MaxLevel, "Unexpected max level value (after 3rd sign request)");
            Assert.IsTrue(resultConf.AggregationAlgorithm == 1 || resultConf.AggregationAlgorithm == 2, "Unexpected algorithm value (after 3rd sign request)");
            Assert.AreEqual(200, resultConf.AggregationPeriod, "Unexpected aggregation period value (after 3rd sign request)");
            Assert.AreEqual(4, resultConf.MaxRequests, "Unexpected max requests value (after 3rd sign request)");
            Assert.AreEqual(1, resultConf.ParentsUris.Count, "Unexpected parent uri count (after 3rd sign request)");
            Assert.IsTrue(resultConf.ParentsUris[0] == "uri-1" || resultConf.ParentsUris[0] == "uri-2", "Unexpected parent uri value at position 0 (after 3rd sign request)");

            // changing aggegation period should change merged config
            newService = (TestKsiService)GetService(new List<PduPayload>()
            {
                GetAggregationResponsePayload(Resources.KsiService_AggregationResponsePdu_RequestId_1584727638),
                GetAggregatorConfigResponsePayload(2, 2, 100, 4, new List<string>() { "uri-2", "uri-3" })
            });

            secondService.SigningServiceProtocol.RequestResult = newService.SigningServiceProtocol.RequestResult;

            waitHandle.Reset();
            resultConf = null;
            changeCount = 0;

            haService.Sign(inputHash);
            waitHandle.WaitOne(1000);
            Assert.IsNotNull(resultConf, "Could not get aggregator config using event handler (after 4th sign request).");

            Assert.AreEqual(2, resultConf.MaxLevel, "Unexpected max level value (after 4th sign request)");
            Assert.IsTrue(resultConf.AggregationAlgorithm == 1 || resultConf.AggregationAlgorithm == 2, "Unexpected algorithm value (after 4th sign request)");
            Assert.AreEqual(100, resultConf.AggregationPeriod, "Unexpected aggregation period value (after 4th sign request)");
            Assert.AreEqual(4, resultConf.MaxRequests, "Unexpected max requests value (after 4th sign request)");
            Assert.AreEqual(1, resultConf.ParentsUris.Count, "Unexpected parent uri count (after 4th sign request)");
            Assert.IsTrue(resultConf.ParentsUris[0] == "uri-1" || resultConf.ParentsUris[0] == "uri-2", "Unexpected parent uri value at position 0 (after 4th sign request)");

            // changing max requests should change merged config
            newService = (TestKsiService)GetService(new List<PduPayload>()
            {
                GetAggregationResponsePayload(Resources.KsiService_AggregationResponsePdu_RequestId_1584727638),
                GetAggregatorConfigResponsePayload(2, 2, 200, 5, new List<string>() { "uri-2", "uri-3" })
            });

            secondService.SigningServiceProtocol.RequestResult = newService.SigningServiceProtocol.RequestResult;

            waitHandle.Reset();
            resultConf = null;
            changeCount = 0;
            haService.Sign(inputHash);
            waitHandle.WaitOne(1000);

            Assert.IsNotNull(resultConf, "Could not get aggregator config using event handler (after 5th sign request).");

            Assert.AreEqual(2, resultConf.MaxLevel, "Unexpected max level value (after 5th sign request)");
            Assert.IsTrue(resultConf.AggregationAlgorithm == 1 || resultConf.AggregationAlgorithm == 2, "Unexpected algorithm value (after 5th sign request)");
            Assert.AreEqual(200, resultConf.AggregationPeriod, "Unexpected aggregation period value (after 5th sign request)");
            Assert.AreEqual(5, resultConf.MaxRequests, "Unexpected max requests value (after 5th sign request)");
            Assert.AreEqual(1, resultConf.ParentsUris.Count, "Unexpected parent uri count (after 5th sign request)");
            Assert.IsTrue(resultConf.ParentsUris[0] == "uri-1" || resultConf.ParentsUris[0] == "uri-2", "Unexpected parent uri value at position 0 (after 5th sign request)");

            // signing again should not change merged config
            waitHandle.Reset();
            resultConf = null;
            changeCount = 0;

            haService.Sign(inputHash);
            waitHandle.WaitOne(1000);
            Assert.IsNull(resultConf, "Aggregator config should have not changed (after 6th sign request");
            Assert.AreEqual(0, changeCount, "Unexpected change count.");
        }

        /// <summary>
        /// Test HA get aggregator config request timeout.
        /// </summary>
        [Test]
        public void HAGetAggregatorConfigTimeoutTest()
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol
            {
                RequestResult = GetAggregatorConfigResponsePayload(1, 2, 100, 4, null).Encode(),
                DelayMilliseconds = 3000
            };

            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(protocol),
                    },
                    null, null, 1000);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.GetAggregatorConfig();
            });

            Assert.That(ex.Message.StartsWith("HA service request timed out"), "Unexpected exception message: " + ex.Message);
        }

        private static HAKsiService GetHAService(params List<PduPayload>[] subServiceResults)
        {
            return new HAKsiService(subServiceResults.Select(payloads => GetService(payloads)).ToList(), null, null);
        }

        private static IKsiService GetService(List<PduPayload> payloads, ulong requestId = 1584727637)
        {
            List<ITlvTag> childTags = new List<ITlvTag> { new PduHeader(Settings.Default.HttpSigningServiceUser) };
            childTags.AddRange(payloads);
            childTags.Add(new ImprintTag(Constants.Pdu.MacTagType, false, false, new DataHash(HashAlgorithm.Sha2256, new byte[32])));

            AggregationResponsePdu pdu = TestUtil.GetCompositeTag<AggregationResponsePdu>(Constants.AggregationResponsePdu.TagType, childTags.ToArray());

            MethodInfo m = pdu.GetType().GetMethod("SetMacValue", BindingFlags.Instance | BindingFlags.NonPublic);
            m.Invoke(pdu, new object[] { HashAlgorithm.Sha2256, Util.EncodeNullTerminatedUtf8String(TestConstants.ServicePass) });

            MemoryStream stream = new MemoryStream();
            using (TlvWriter writer = new TlvWriter(stream))
            {
                writer.WriteTag(pdu);
            }

            return GetStaticKsiService(stream.ToArray(), requestId);
        }

        private static AggregationResponsePayload GetAggregationResponsePayload(string path)
        {
            byte[] bytes = File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, path));

            using (TlvReader reader = new TlvReader(new MemoryStream(bytes)))
            {
                AggregationResponsePdu pdu = new AggregationResponsePdu(reader.ReadTag());
                return pdu.Payloads[0] as AggregationResponsePayload;
            }
        }

        private static AggregatorConfigResponsePayload GetAggregatorConfigResponsePayload(ulong? maxLevel, ulong? aggregationAlgorithm, ulong? aggregationPeriod,
                                                                                          ulong? maxRequests,
                                                                                          IList<string> parentsUris)
        {
            List<ITlvTag> tlvTags = new List<ITlvTag>();

            if (maxLevel.HasValue)
            {
                tlvTags.Add(new IntegerTag(Constants.AggregatorConfigResponsePayload.MaxLevelTagType, false, false, maxLevel.Value));
            }
            if (aggregationAlgorithm.HasValue)
            {
                tlvTags.Add(new IntegerTag(Constants.AggregatorConfigResponsePayload.AggregationAlgorithmTagType, false, false, aggregationAlgorithm.Value));
            }
            if (aggregationPeriod.HasValue)
            {
                tlvTags.Add(new IntegerTag(Constants.AggregatorConfigResponsePayload.AggregationPeriodTagType, false, false, aggregationPeriod.Value));
            }
            if (maxRequests.HasValue)
            {
                tlvTags.Add(new IntegerTag(Constants.AggregatorConfigResponsePayload.MaxRequestsTagType, false, false, maxRequests.Value));
            }
            if (parentsUris != null)
            {
                tlvTags.AddRange(parentsUris.Select(uri => new StringTag(Constants.AggregatorConfigResponsePayload.ParentUriTagType, false, false, uri)));
            }

            AggregatorConfigResponsePayload payload = TestUtil.GetCompositeTag<AggregatorConfigResponsePayload>(Constants.AggregatorConfigResponsePayload.TagType,
                tlvTags.ToArray());
            return payload;
        }
    }
}