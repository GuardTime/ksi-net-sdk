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
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Service;
using Guardtime.KSI.Service.HighAvailability;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service.HighAvailability
{
    /// <summary>
    /// High availability signing tests with static response
    /// </summary>
    [TestFixture]
    public class HASigningStaticTests : StaticServiceTestsBase
    {
        /// <summary>
        /// Test signing without signing services.
        /// </summary>
        [Test]
        public void HASignWithoutServicesFailStaticTest()
        {
            IKsiService haService =
                new HAKsiService(
                    null,
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1),
                    },
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1),
                    });

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.Sign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
            });

            Assert.That(ex.Message.StartsWith("Sub-services are missing"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing with single sub-service
        /// </summary>
        [Test]
        public void HASignWithSingleServiceStaticTest()
        {
            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637)
                    },
                    null, null);

            DataHash inputHash = new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            IKsiSignature signature = haService.Sign(inputHash);

            Assert.AreEqual(inputHash, signature.InputHash, "Unexpected signature input hash.");
        }

        /// <summary>
        /// Test signing with multiple sub-service.
        /// </summary>
        [Test]
        public void HASignStaticTest()
        {
            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727638),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637)
                    },
                    null, null);

            IKsiSignature signature = haService.Sign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
            Assert.IsNotNull(signature, "Signature cannot be null.");
        }

        /// <summary>
        /// Test get sign response payload
        /// </summary>
        [Test]
        public void HASignWithPayloadResponseStaticTest()
        {
            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727638),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1584727637)
                    },
                    null, null);

            IAsyncResult ar = haService.BeginSign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")), null, null);
            SignRequestResponsePayload payload = haService.GetSignResponsePayload(ar);
            Assert.IsNotNull(payload, "Sign request response payload cannot be null.");
        }

        /// <summary>
        /// Test signing with all sub-requests failing.
        /// </summary>
        [Test]
        public void HASignFailStaticTest()
        {
            IKsiService haService =
                new HAKsiService(
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 1),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)), 2),
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455)
                    },
                    null, null);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                haService.Sign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
            });

            Assert.That(ex.Message.StartsWith("All sub-requests failed"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing with invalid async result.
        /// </summary>
        [Test]
        public void HASignWithInvalidAsyncResultFailStaticTest()
        {
            IKsiService haService =
                new HAKsiService(
                    null,
                    new List<IKsiService>()
                    {
                        GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455)
                    },
                    null);

            HAKsiServiceException ex = Assert.Throws<HAKsiServiceException>(delegate
            {
                IAsyncResult ar = haService.BeginExtend(1455494400, null, null);
                // send extending async result to sign ending
                haService.EndSign(ar);
            });

            Assert.That(ex.Message.StartsWith("Invalid async result. Containing invalid request runner"), "Unexpected exception message: " + ex.Message);
        }
    }
}