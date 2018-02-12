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
    public class HAExtenderConfigStaticTests : StaticServiceTestsBase
    {
        [Test]
        public void HAExtenderConfigRequestWithSingleServiceTest()
        {
            // Test getting extender configuration with single sub-service
            IKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetExtenderConfigResponsePayload(4, new List<string>() { "uri-1" }, 1136073600, 2136073600)
                });

            haService.GetExtenderConfig();

            ExtenderConfig config = haService.GetExtenderConfig();

            Assert.AreEqual(4, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, config.ParentsUris.Count, "Unexpected parent uri count");
            Assert.AreEqual("uri-1", config.ParentsUris[0], "Unexpected parent uri value at position 0");
            Assert.AreEqual(1136073600, config.CalendarFirstTime, "Unexpected calendar first time value");
            Assert.AreEqual(2136073600, config.CalendarLastTime, "Unexpected calendar last time value");
        }

        [Test]
        public void HAExtenderConfigRequestTest()
        {
            // Test getting extender configuration with 1 successful and 2 unsuccessful sub-service responses 

            IKsiService haService =
                new HAKsiService(
                    null,
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtenderConfigResponsePdu)), 1584727637),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101454)
                    },
                    null);

            ExtenderConfig config = haService.GetExtenderConfig();

            Assert.AreEqual(273, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(0, config.ParentsUris.Count, "Unexpected parent uri count");
            Assert.AreEqual(1455478441, config.CalendarFirstTime, "Unexpected calendar first time value");
            Assert.AreEqual(1455478442, config.CalendarLastTime, "Unexpected calendar last time value");
        }

        [Test]
        public void HAExtenderConfigRequestUsingEventHandlerTest()
        {
            // Test getting extender configuration with 1 successful and 2 unsuccessful sub-service responses. 
            // Get response using ExtenderConfigChanged event handler

            IKsiService haService =
                new HAKsiService(
                    null,
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtenderConfigResponsePdu)), 1584727637),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101454)
                    },
                    null);

            ManualResetEvent waitHandle = new ManualResetEvent(false);
            ExtenderConfig config = null;

            haService.ExtenderConfigChanged += delegate(object sender, ExtenderConfigChangedEventArgs e)
            {
                config = e.ExtenderConfig;
                waitHandle.Set();
            };
            haService.GetExtenderConfig();
            waitHandle.WaitOne(1000);
            Assert.IsNotNull(config, "Could not get extender config using event handler.");

            Assert.AreEqual(273, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(0, config.ParentsUris.Count, "Unexpected parent uri count");
            Assert.AreEqual(1455478441, config.CalendarFirstTime, "Unexpected calendar first time value");
            Assert.AreEqual(1455478442, config.CalendarLastTime, "Unexpected calendar last time value");
        }

        [Test]
        public void HAExtenderConfigRequestFailTest()
        {
            // Test getting extender configuration with all 3 sub-services responses failing

            IKsiService haService =
                new HAKsiService(
                    null,
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 2),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 3)
                    },
                    null);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.GetExtenderConfig();
            });

            Assert.That(ex.Message.StartsWith("Could not get extender configuration"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void HAGetConfigSingleResultAllNullsTest()
        {
            // Test getting extender configuration with 1 successful sub-service response
            // All the values are empty

            IKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetExtenderConfigResponsePayload(null, null, null, null),
                });

            ExtenderConfig config = haService.GetExtenderConfig();

            Assert.IsNull(config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(0, config.ParentsUris.Count, "Unexpected parent uri list");
            Assert.IsNull(config.CalendarFirstTime, "Unexpected calendar first time value");
            Assert.IsNull(config.CalendarLastTime, "Unexpected calendar last time value");
        }

        [Test]
        public void HAGetConfigTwoResultsTest1()
        {
            // Test getting extender configuration with 2 successful sub-service responses

            IKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetExtenderConfigResponsePayload(4, null, 1136073601, 2136073600),
                },
                new List<PduPayload>()
                {
                    GetExtenderConfigResponsePayload(5, new List<string>() { "uri-2" }, 1136073600, 2136073601)
                });

            ExtenderConfig config = haService.GetExtenderConfig();

            Assert.AreEqual(5, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, config.ParentsUris.Count, "Unexpected parent uri count");
            Assert.AreEqual("uri-2", config.ParentsUris[0], "Unexpected parent uri value at position 0");
            Assert.AreEqual(1136073600, config.CalendarFirstTime, "Unexpected calendar first time value");
            Assert.AreEqual(2136073601, config.CalendarLastTime, "Unexpected calendar last time value");
        }

        [Test]
        public void HAGetConfigTwoResultsTest2()
        {
            // Test getting extender configuration with 2 successful sub-service responses

            IKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetExtenderConfigResponsePayload(5, new List<string>() { "uri-1" }, 1136073600, 1136073601),
                },
                new List<PduPayload>()
                {
                    GetExtenderConfigResponsePayload(4, new List<string>() { "uri-2" }, 1136073601, 1136073600)
                });

            ExtenderConfig config = haService.GetExtenderConfig();

            Assert.AreEqual(5, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, config.ParentsUris.Count, "Unexpected parent uri count");
            Assert.IsTrue(config.ParentsUris[0] == "uri-1" || config.ParentsUris[0] == "uri-2", "Unexpected parent uri value at position 0");
            Assert.AreEqual(1136073600, config.CalendarFirstTime, "Unexpected calendar first time value");
            Assert.AreEqual(1136073601, config.CalendarLastTime, "Unexpected calendar last time value");
        }

        [Test]
        public void HAGetConfigTwoResultsTest3()
        {
            // Test getting extender configuration with 2 successful sub-service responses

            IKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetExtenderConfigResponsePayload(null, null, null, null),
                },
                new List<PduPayload>()
                {
                    GetExtenderConfigResponsePayload(4, new List<string>() { "uri-2" }, 1136073600, 2136073600)
                });

            ExtenderConfig config = haService.GetExtenderConfig();
            Assert.AreEqual(4, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, config.ParentsUris.Count, "Unexpected parent uri count");
            Assert.AreEqual("uri-2", config.ParentsUris[0], "Unexpected parent uri value at position 0");
            Assert.AreEqual(1136073600, config.CalendarFirstTime, "Unexpected calendar first time value");
            Assert.AreEqual(2136073600, config.CalendarLastTime, "Unexpected calendar last time value");
        }

        [Test]
        public void HAGetConfigTwoResultsTest4()
        {
            // Test getting extender configuration with 2 successful sub-service responses

            IKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetExtenderConfigResponsePayload(4, new List<string>() { "uri-1" }, 1136073601, 1136073602),
                },
                new List<PduPayload>()
                {
                    GetExtenderConfigResponsePayload(null, null, null, null)
                });

            ExtenderConfig config = haService.GetExtenderConfig();

            Assert.AreEqual(4, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, config.ParentsUris.Count, "Unexpected parent uri count");
            Assert.AreEqual("uri-1", config.ParentsUris[0], "Unexpected parent uri value at position 0");
            Assert.AreEqual(1136073601, config.CalendarFirstTime, "Unexpected calendar first time value");
            Assert.AreEqual(1136073602, config.CalendarLastTime, "Unexpected calendar last time value");
        }

        [Test]
        public void HAGetConfigResultsOutOfLimitTest()
        {
            // Test getting extender configuration with 2 successful sub-service responses
            // Some values are out of bounds

            IKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetExtenderConfigResponsePayload(4, new List<string>() { "uri-1" }, 1136073601, 1136073600)
                },
                new List<PduPayload>()
                {
                    GetExtenderConfigResponsePayload(16001, null, 1136073599, 1136073598)
                });

            ExtenderConfig config = haService.GetExtenderConfig();

            Assert.AreEqual(4, config.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, config.ParentsUris.Count, "Unexpected parent uri count");
            Assert.AreEqual("uri-1", config.ParentsUris[0], "Unexpected parent uri value at position 0");
            Assert.AreEqual(1136073601, config.CalendarFirstTime, "Unexpected calendar first time value");
            Assert.IsNull(config.CalendarLastTime, "Unexpected calendar last time value");
        }

        [Test]
        public void HAGetConfigResultsAndRemoveAllTest()
        {
            // A configuration request with 2 successful sub-requests is made.
            // Then a new configuration request is made with 2 unsuccessful sub-requests. 
            // Both configuration are removed from cache.
            // ExtenderConfigChanged event handler should get result containing an exception.

            HAKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetExtenderConfigResponsePayload(4, new List<string>() { "uri-1" }, 1136073600, 2136073600)
                },
                new List<PduPayload>()
                {
                    GetExtenderConfigResponsePayload(4, new List<string>() { "uri-2" }, 1136073600, 2136073600)
                });

            haService.GetExtenderConfig();

            // change first service response so that request fails
            ((TestKsiService)haService.ExtendingServices[0]).ExtendingServiceProtocol.RequestResult =
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455));

            // change second service response so that request fails
            ((TestKsiService)haService.ExtendingServices[1]).ExtendingServiceProtocol.RequestResult =
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455));

            ExtenderConfigChangedEventArgs args = null;
            ManualResetEvent waitHandle = new ManualResetEvent(false);

            haService.ExtenderConfigChanged += delegate(object sender, ExtenderConfigChangedEventArgs e)
            {
                args = e;
                waitHandle.Set();
            };

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.GetExtenderConfig();
            });

            Assert.That(ex.Message.StartsWith("Could not get extender configuration"), "Unexpected exception message: " + ex.Message);

            waitHandle.WaitOne(1000);

            Assert.IsNotNull(args, "ExtenderConfigChangedEventArgs cannot be null.");
            Assert.IsNull(args.ExtenderConfig, "ExtenderConfigChangedEventArgs.ExtenderConfig cannot have value.");
            Assert.IsNotNull(args.Exception, "ExtenderConfigChangedEventArgs.Exception cannot be null.");
            Assert.AreEqual(haService, args.KsiService, "Unexpected ExtenderConfigChangedEventArgs.KsiService");
            Assert.That(args.Exception.Message.StartsWith("Could not get extender configuration"), "Unexpected exception message: " + args.Exception.Message);
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
                    GetExtenderConfigResponsePayload(4, new List<string>() { "uri-1" }, 1136073601, 2136073601)
                },
                new List<PduPayload>()
                {
                    GetExtenderConfigResponsePayload(4, new List<string>() { "uri-2" }, 1136073601, 2136073601)
                });

            ManualResetEvent waitHandle = new ManualResetEvent(false);

            haService.ExtenderConfigChanged += delegate
            {
            };

            ExtenderConfig resultConf = haService.GetExtenderConfig();
            waitHandle.WaitOne(1000);

            Assert.AreEqual(4, resultConf.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, resultConf.ParentsUris.Count, "Unexpected parent uri count");
            Assert.AreEqual(1136073601, resultConf.CalendarFirstTime, "Unexpected calendar first time value");
            Assert.AreEqual(2136073601, resultConf.CalendarLastTime, "Unexpected calendar last time value");

            // change first service response so that request fails
            ((TestKsiService)haService.ExtendingServices[0]).ExtendingServiceProtocol.RequestResult =
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455));

            // change second service response so that a valid configuration is returned
            TestKsiService newService = (TestKsiService)GetService(new List<PduPayload>()
            {
                GetExtendResponsePayload(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455),
                GetExtenderConfigResponsePayload(3, new List<string>() { "uri-2-changed" }, 1136073602, 2136073600)
            });

            ((TestKsiService)haService.ExtendingServices[1]).ExtendingServiceProtocol.RequestResult = newService.ExtendingServiceProtocol.RequestResult;

            ExtenderConfigChangedEventArgs args = null;
            waitHandle = new ManualResetEvent(false);

            haService.ExtenderConfigChanged += delegate(object sender, ExtenderConfigChangedEventArgs e)
            {
                args = e;
            };

            resultConf = haService.GetExtenderConfig();

            Assert.AreEqual(3, resultConf.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, resultConf.ParentsUris.Count, "Unexpected parent uri count");
            Assert.AreEqual("uri-2-changed", resultConf.ParentsUris[0], "Unexpected parent uri value at position 0");
            Assert.AreEqual(1136073602, resultConf.CalendarFirstTime, "Unexpected calendar first time value");
            Assert.AreEqual(2136073600, resultConf.CalendarLastTime, "Unexpected calendar last time value");

            waitHandle.WaitOne(1000);

            Assert.IsNotNull(args, "ExtenderConfigChangedEventArgs cannot be null.");
            Assert.AreEqual(resultConf, args.ExtenderConfig, "Unexpected ExtenderConfigChangedEventArgs.ExtenderConfig.");
            Assert.IsNull(args.Exception, "ExtenderConfigChangedEventArgs.Exception cannot have value.");
            Assert.AreEqual(haService, args.KsiService, "Unexpected ExtenderConfigChangedEventArgs.KsiService");
        }

        [Test]
        public void HAGetConfigResultsWithExtendRequestTest()
        {
            // Test getting extender configurations via ExtenderConfigChanged event handler when using Extend method.
            // Testing getting different configurations in a sequence

            HAKsiService haService = GetHAService(
                new List<PduPayload>()
                {
                    GetExtendResponsePayload(Resources.KsiService_ExtendResponsePdu_RequestId_1043101454),
                    GetExtenderConfigResponsePayload(4, new List<string>() { "uri-1" }, 1136073601, 1136073602)
                },
                new List<PduPayload>()
                {
                    GetExtendResponsePayload(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455),
                    GetExtenderConfigResponsePayload(4, new List<string>() { "uri-2" }, 1136073601, 1136073602)
                });

            TestKsiService secondService = (TestKsiService)haService.ExtendingServices[1];
            secondService.RequestId = 1043101455;

            ExtenderConfig resultConf = null;
            int changeCount = 0;
            ManualResetEvent waitHandle = new ManualResetEvent(false);

            haService.ExtenderConfigChanged += delegate(object sender, ExtenderConfigChangedEventArgs e)
            {
                resultConf = e.ExtenderConfig;
                changeCount++;
                if (changeCount == 2)
                {
                    waitHandle.Set();
                }
            };

            CalendarHashChain cal = haService.Extend(123);

            Assert.AreEqual(1455494400, cal.PublicationTime, "Unexpected calendar hash chain publication time.");
            waitHandle.WaitOne(1000);
            Assert.IsNotNull(resultConf, "Could not get extender config using event handler.");

            Assert.AreEqual(4, resultConf.MaxRequests, "Unexpected max requests value");
            Assert.AreEqual(1, resultConf.ParentsUris.Count, "Unexpected parent uri count");
            Assert.IsTrue(resultConf.ParentsUris[0] == "uri-1" || resultConf.ParentsUris[0] == "uri-2", "Unexpected parent uri value at position 0");
            Assert.AreEqual(1136073601, resultConf.CalendarFirstTime, "Unexpected calendar first time value");
            Assert.AreEqual(1136073602, resultConf.CalendarLastTime, "Unexpected calendar last time value");

            // changing extender algorithm or parent uri should not change merged config
            TestKsiService newService = (TestKsiService)GetService(new List<PduPayload>()
            {
                GetExtendResponsePayload(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455),
                GetExtenderConfigResponsePayload(4, new List<string>() { "uri-2-changed" }, 1136073601, 1136073602)
            });

            secondService.ExtendingServiceProtocol.RequestResult = newService.ExtendingServiceProtocol.RequestResult;

            resultConf = null;
            changeCount = 0;
            haService.Extend(123);
            Thread.Sleep(1000);
            Assert.IsNull(resultConf, "Extender config should have not changed (2nd request)");
            Assert.AreEqual(0, changeCount, "Unexpected change count (2nd request)");

            // changing max requests should change merged config
            newService = (TestKsiService)GetService(new List<PduPayload>()
            {
                GetExtendResponsePayload(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455),
                GetExtenderConfigResponsePayload(5, new List<string>() { "uri-2" }, 1136073601, 1136073602)
            });

            secondService.ExtendingServiceProtocol.RequestResult = newService.ExtendingServiceProtocol.RequestResult;

            waitHandle.Reset();
            resultConf = null;
            changeCount = 0;
            haService.Extend(123);
            waitHandle.WaitOne(1000);

            Assert.IsNotNull(resultConf, "Could not get extender config using event handler (after 3rd extend request).");

            Assert.AreEqual(5, resultConf.MaxRequests, "Unexpected max requests value (after 3rd extend request)");
            Assert.AreEqual(1, resultConf.ParentsUris.Count, "Unexpected parent uri count (after 3rd extend request)");
            Assert.IsTrue(resultConf.ParentsUris[0] == "uri-1" || resultConf.ParentsUris[0] == "uri-2", "Unexpected parent uri value at position 0 (after 3rd extend request)");
            Assert.AreEqual(1136073601, resultConf.CalendarFirstTime, "Unexpected calendar first time value (after 3rd extend request)");
            Assert.AreEqual(1136073602, resultConf.CalendarLastTime, "Unexpected calendar last time value (after 3rd extend request)");

            // changing first time should change merged config
            newService = (TestKsiService)GetService(new List<PduPayload>()
            {
                GetExtendResponsePayload(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455),
                GetExtenderConfigResponsePayload(5, new List<string>() { "uri-2" }, 1136073600, 1136073602)
            });

            secondService.ExtendingServiceProtocol.RequestResult = newService.ExtendingServiceProtocol.RequestResult;

            waitHandle.Reset();
            resultConf = null;
            changeCount = 0;

            haService.Extend(123);
            waitHandle.WaitOne(1000);
            Assert.IsNotNull(resultConf, "Could not get extender config using event handler (after 4th extend request).");

            Assert.AreEqual(5, resultConf.MaxRequests, "Unexpected max requests value (after 4th extend request)");
            Assert.AreEqual(1, resultConf.ParentsUris.Count, "Unexpected parent uri count (after 4th extend request)");
            Assert.IsTrue(resultConf.ParentsUris[0] == "uri-1" || resultConf.ParentsUris[0] == "uri-2", "Unexpected parent uri value at position 0 (after 4th extend request)");
            Assert.AreEqual(1136073600, resultConf.CalendarFirstTime, "Unexpected calendar first time value (after 4th extend request)");
            Assert.AreEqual(1136073602, resultConf.CalendarLastTime, "Unexpected calendar last time value (after 4th extend request)");

            // changing last time should change merged config
            newService = (TestKsiService)GetService(new List<PduPayload>()
            {
                GetExtendResponsePayload(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455),
                GetExtenderConfigResponsePayload(5, new List<string>() { "uri-2" }, 1136073600, 1136073603)
            });

            secondService.ExtendingServiceProtocol.RequestResult = newService.ExtendingServiceProtocol.RequestResult;

            waitHandle.Reset();
            resultConf = null;
            changeCount = 0;

            haService.Extend(123);
            waitHandle.WaitOne(1000);
            Assert.IsNotNull(resultConf, "Could not get extender config using event handler (after 5th extend request).");

            Assert.AreEqual(5, resultConf.MaxRequests, "Unexpected max requests value (after 5th extend request)");
            Assert.AreEqual(1, resultConf.ParentsUris.Count, "Unexpected parent uri count (after 5th extend request)");
            Assert.IsTrue(resultConf.ParentsUris[0] == "uri-1" || resultConf.ParentsUris[0] == "uri-2", "Unexpected parent uri value at position 0 (after 5th extend request)");
            Assert.AreEqual(1136073600, resultConf.CalendarFirstTime, "Unexpected calendar first time value (after 5th extend request)");
            Assert.AreEqual(1136073603, resultConf.CalendarLastTime, "Unexpected calendar last time value (after 5th extend request)");

            // extending again should not change merged config
            waitHandle.Reset();
            resultConf = null;
            changeCount = 0;

            haService.Extend(123);
            waitHandle.WaitOne(1000);
            Assert.IsNull(resultConf, "Extender config should have not changed (after 6th extend request)");
            Assert.AreEqual(0, changeCount, "Unexpected change count.");
        }

        /// <summary>
        /// Test HA get extender config request timeout.
        /// </summary>
        [Test]
        public void HAGetExtenderConfigTimeoutTest()
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol
            {
                RequestResult = GetExtenderConfigResponsePayload(1, null, 123, 234).Encode(),
                DelayMilliseconds = 3000
            };

            IKsiService haService =
                new HAKsiService(
                    null, new List<IKsiService>()
                    {
                        GetStaticKsiService(protocol),
                    },
                    null, 1000);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.GetExtenderConfig();
            });

            Assert.That(ex.Message.StartsWith("HA service request timed out"), "Unexpected exception message: " + ex.Message);
        }

        private static HAKsiService GetHAService(params List<PduPayload>[] subServiceResults)
        {
            return new HAKsiService(null, subServiceResults.Select(payloads => GetService(payloads)).ToList(), null);
        }

        private static IKsiService GetService(List<PduPayload> payloads, ulong requestId = 1584727637)
        {
            List<ITlvTag> childTags = new List<ITlvTag> { new PduHeader(Settings.Default.HttpExtendingServiceUser) };
            childTags.AddRange(payloads);
            childTags.Add(new ImprintTag(Constants.Pdu.MacTagType, false, false, new DataHash(HashAlgorithm.Sha2256, new byte[32])));

            ExtendResponsePdu pdu = TestUtil.GetCompositeTag<ExtendResponsePdu>(Constants.ExtendResponsePdu.TagType, childTags.ToArray());

            MethodInfo m = pdu.GetType().GetMethod("SetMacValue", BindingFlags.Instance | BindingFlags.NonPublic);
            m.Invoke(pdu, new object[] { HashAlgorithm.Sha2256, Util.EncodeNullTerminatedUtf8String(TestConstants.ServicePass) });

            MemoryStream stream = new MemoryStream();
            using (TlvWriter writer = new TlvWriter(stream))
            {
                writer.WriteTag(pdu);
            }

            return GetStaticKsiService(stream.ToArray(), requestId);
        }

        private static ExtendResponsePayload GetExtendResponsePayload(string path)
        {
            byte[] bytes = File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, path));

            using (TlvReader reader = new TlvReader(new MemoryStream(bytes)))
            {
                ExtendResponsePdu pdu = new ExtendResponsePdu(reader.ReadTag());
                return pdu.Payloads[0] as ExtendResponsePayload;
            }
        }

        private static ExtenderConfigResponsePayload GetExtenderConfigResponsePayload(ulong? maxRequests, IList<string> parentsUris, ulong? calendarFirstTime,
                                                                                      ulong? calendarLastTime)
        {
            List<ITlvTag> tlvTags = new List<ITlvTag>();

            if (maxRequests.HasValue)
            {
                tlvTags.Add(new IntegerTag(Constants.ExtenderConfigResponsePayload.MaxRequestsTagType, false, false, maxRequests.Value));
            }
            if (parentsUris != null)
            {
                tlvTags.AddRange(parentsUris.Select(uri => new StringTag(Constants.ExtenderConfigResponsePayload.ParentUriTagType, false, false, uri)));
            }
            if (calendarFirstTime.HasValue)
            {
                tlvTags.Add(new IntegerTag(Constants.ExtenderConfigResponsePayload.CalendarFirstTimeTagType, false, false, calendarFirstTime.Value));
            }
            if (calendarLastTime.HasValue)
            {
                tlvTags.Add(new IntegerTag(Constants.ExtenderConfigResponsePayload.CalendarLastTimeTagType, false, false, calendarLastTime.Value));
            }

            ExtenderConfigResponsePayload payload = TestUtil.GetCompositeTag<ExtenderConfigResponsePayload>(Constants.ExtenderConfigResponsePayload.TagType,
                tlvTags.ToArray());
            return payload;
        }
    }
}