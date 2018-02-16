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
using System.Threading;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Service.HighAvailability;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Integration
{
    /// <summary>
    /// High availability tests
    /// </summary>
    [TestFixture]
    public class HATests : IntegrationTests
    {
        private static readonly List<IKsiService> SigningServices = new List<IKsiService>()
        {
            GetHttpKsiServiceWithInvalidSigningPass(),
            GetHttpKsiService(),
            GetTcpKsiService()
        };

        private static readonly List<IKsiService> ExtendingServices = new List<IKsiService>()
        {
            GetHttpKsiServiceWithInvalidExtendingPass(),
            GetTcpKsiService(),
            GetHttpKsiService()
        };

        private static readonly IKsiService PublicationsFileService = GetHttpKsiService();

        /// <summary>
        /// Test signing TCP and HTTP signing services.
        /// </summary>
        [Test]
        public void HASignWithTcpAndHttpServicesTest()
        {
            Ksi ksi = new Ksi(new HAKsiService(SigningServices, null, null));
            DataHash hash = new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));

            IKsiSignature signature = ksi.Sign(hash);

            Assert.NotNull(signature);
            Assert.AreEqual(hash, signature.InputHash);
            Assert.AreEqual(0L, signature.GetAggregationHashChains()[0].GetChainLinks()[0].LevelCorrection);
        }

        /// <summary>
        /// Test signing with level.
        /// </summary>
        [Test]
        public void HASignWithLevelTest()
        {
            Ksi ksi = new Ksi(new HAKsiService(SigningServices, null, null));
            DataHash hash = new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a10"));

            IKsiSignature signature = ksi.Sign(hash, 3);

            Assert.NotNull(signature);
            Assert.AreEqual(hash, signature.InputHash);
            Assert.AreEqual(3L, signature.GetAggregationHashChains()[0].GetChainLinks()[0].LevelCorrection);
        }

        /// <summary>
        /// Get aggregator conf with TCP and HTTP sercices.
        /// </summary>
        [Test]
        public void HAAggregatorGetConfTest()
        {
            Ksi ksi = new Ksi(new HAKsiService(SigningServices, null, null));
            AggregatorConfig conf = ksi.GetAggregatorConfig();
            Assert.NotNull(conf);
        }

        /// <summary>
        /// Extend signature using TCP and HTTP services.
        /// </summary>
        [Test]
        public void HAExtendWithTcpAndHttpServicesTest()
        {
            Ksi ksi = new Ksi(new HAKsiService(null, ExtendingServices, PublicationsFileService));
            IKsiSignature ksiSignature = TestUtil.GetSignature();
            IKsiSignature extenderSiganture = ksi.Extend(ksiSignature);
            Assert.IsFalse(ksiSignature.IsExtended);
            Assert.NotNull(extenderSiganture);
            Assert.IsTrue(extenderSiganture.IsExtended);
        }

        /// <summary>
        /// Extend signature using TCP and HTTP services while publications file is not available.
        /// </summary>
        [Test]
        public void HAExtendWithTcpAndHttpServicesAndNoPublicationsFileTest()
        {
            Ksi ksi = new Ksi(new HAKsiService(null, ExtendingServices, null));
            IKsiSignature ksiSignature = TestUtil.GetSignature();
            Exception ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                ksi.Extend(ksiSignature);
            });
            Assert.IsFalse(ksiSignature.IsExtended);
            Assert.That(ex.Message.StartsWith("Publications file service is missing"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Get extender conf with TCP and HTTP sercices.
        /// </summary>
        [Test]
        public void HAExtenderGetConfTest()
        {
            Ksi ksi = new Ksi(new HAKsiService(null, ExtendingServices, null));
            ExtenderConfig conf = ksi.GetExtenderConfig();
            Assert.NotNull(conf);
        }

        /// <summary>
        /// Get extender conf with TCP and HTTP sercices.
        /// </summary>
        [Test]
        public void HARequestSubClientsTest()
        {
            HAKsiService haService = new HAKsiService(SigningServices, ExtendingServices, PublicationsFileService);
            Assert.AreEqual(ExtendingServices, haService.ExtendingServices);
            Assert.AreEqual(SigningServices, haService.SigningServices);
        }

        [Test]
        public void HAAsyncSignTest()
        {
            HAKsiService haService = new HAKsiService(SigningServices, ExtendingServices, PublicationsFileService);

            DataHash dataHash = new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            ManualResetEvent waitHandle = new ManualResetEvent(false);
            IKsiSignature signature = null;
            object testObject = new object();
            bool isAsyncStateCorrect = false;

            haService.BeginSign(dataHash, delegate(IAsyncResult ar)
            {
                try
                {
                    isAsyncStateCorrect = ar.AsyncState == testObject;
                    signature = haService.EndSign(ar);
                }
                finally
                {
                    waitHandle.Set();
                }
            }, testObject);

            Assert.IsTrue(waitHandle.WaitOne(10000), "Wait handle timed out.");

            Assert.IsNotNull(signature, "Signature should not be null.");
            Assert.AreEqual(true, isAsyncStateCorrect, "Unexpected async state.");
        }

        [Test]
        public void HAAsyncGetAggregatorConfigTest()
        {
            HAKsiService haService = new HAKsiService(SigningServices, ExtendingServices, PublicationsFileService);

            ManualResetEvent waitHandle = new ManualResetEvent(false);
            AggregatorConfig config = null;
            object testObject = new object();
            bool isAsyncCorrect = false;

            haService.BeginGetAggregatorConfig(delegate(IAsyncResult ar)
            {
                try
                {
                    isAsyncCorrect = ar.AsyncState == testObject;
                    config = haService.EndGetAggregatorConfig(ar);
                }
                finally
                {
                    waitHandle.Set();
                }
            }, testObject);

            Assert.IsTrue(waitHandle.WaitOne(10000), "Wait handle timed out.");

            Assert.IsNotNull(config, "Aggregator configuration should not be null.");
            Assert.AreEqual(true, isAsyncCorrect, "Unexpected async state.");
        }

        [Test]
        public void HAAsyncExtendTest()
        {
            HAKsiService haService = new HAKsiService(SigningServices, ExtendingServices, PublicationsFileService);

            ManualResetEvent waitHandle = new ManualResetEvent(false);
            CalendarHashChain cal = null;

            object testObject = new object();
            bool isAsyncCorrect = false;

            haService.BeginExtend(1455400000, delegate(IAsyncResult ar)
            {
                try
                {
                    isAsyncCorrect = ar.AsyncState == testObject;
                    cal = haService.EndExtend(ar);
                }
                finally
                {
                    waitHandle.Set();
                }
            }, testObject);

            Assert.IsTrue(waitHandle.WaitOne(10000), "Wait handle timed out.");

            Assert.IsNotNull(cal, "Calendar hash chain should not be null.");
            Assert.AreEqual(true, isAsyncCorrect, "Unexpected async state.");
        }

        [Test]
        public void AsyncGetExtenderConfigTest()
        {
            HAKsiService haService = new HAKsiService(SigningServices, ExtendingServices, PublicationsFileService);

            ManualResetEvent waitHandle = new ManualResetEvent(false);
            ExtenderConfig config = null;
            object testObject = new object();
            bool isAsyncCorrect = false;

            haService.BeginGetExtenderConfig(delegate(IAsyncResult ar)
            {
                try
                {
                    isAsyncCorrect = ar.AsyncState == testObject;
                    config = haService.EndGetExtenderConfig(ar);
                }
                finally
                {
                    waitHandle.Set();
                }
            }, testObject);

            Assert.IsTrue(waitHandle.WaitOne(10000), "Wait handle timed out.");

            Assert.IsNotNull(config, "Extender configuration should not be null.");
            Assert.AreEqual(true, isAsyncCorrect, "Unexpected async state.");
        }

        [Test]
        public void HttpAsyncGetPublicationsFileTest()
        {
            HAKsiService haService = new HAKsiService(SigningServices, ExtendingServices, PublicationsFileService);

            ManualResetEvent waitHandle = new ManualResetEvent(false);
            IPublicationsFile pubFile = null;

            object testObject = new object();
            bool isAsyncCorrect = false;

            haService.BeginGetPublicationsFile(delegate(IAsyncResult ar)
            {
                try
                {
                    isAsyncCorrect = ar.AsyncState == testObject;
                    pubFile = haService.EndGetPublicationsFile(ar);
                }
                finally
                {
                    waitHandle.Set();
                }
            }, testObject);

            Assert.IsTrue(waitHandle.WaitOne(10000), "Wait handle timed out.");

            Assert.IsNotNull(pubFile, "Publications file should not be null.");
            Assert.AreEqual(true, isAsyncCorrect, "Unexpected async state.");
        }
    }
}