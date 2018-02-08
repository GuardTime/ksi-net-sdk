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
using System.Threading;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Integration
{
    public class PublicationsFileIntegrationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void GetPublicationsFileTest(Ksi ksi)
        {
            IPublicationsFile publicationsFile = ksi.GetPublicationsFile();

            PublicationRecordInPublicationFile latest = publicationsFile.GetLatestPublication();
            PublicationRecordInPublicationFile prev = publicationsFile.GetNearestPublicationRecord(latest.PublicationData.PublicationTime - 35 * 24 * 3600);
            Assert.True(latest.PublicationData.PublicationTime > prev.PublicationData.PublicationTime);
            prev = publicationsFile.GetNearestPublicationRecord(Util.ConvertUnixTimeToDateTime(latest.PublicationData.PublicationTime).AddDays(-35));
            Assert.True(latest.PublicationData.PublicationTime > prev.PublicationData.PublicationTime);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsiWithInvalidPublicationsFileUrl))]
        public void GetPublicationsFileWithInvalidUrlTest(Ksi ksi)
        {
            Exception ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                ksi.GetPublicationsFile();
            });

            Assert.That(ex.Message.StartsWith("Get publication http response failed"), "Unexpected exception message: " + ex.Message);
            Assert.IsNotNull(ex.InnerException, "Inner exception should not be null");
            Assert.That(ex.InnerException.Message.StartsWith("The remote name could not be resolved"), "Unexpected inner exception message: " + ex.InnerException.Message);
        }

        [Test]
        public void HttpAsyncGetPublicationsFileTest()
        {
            KsiService service = GetHttpKsiService();

            ManualResetEvent waitHandle = new ManualResetEvent(false);
            IPublicationsFile pubFile = null;

            object testObject = new object();
            bool isAsyncCorrect = false;

            service.BeginGetPublicationsFile(delegate(IAsyncResult ar)
            {
                try
                {
                    isAsyncCorrect = ar.AsyncState == testObject;
                    pubFile = service.EndGetPublicationsFile(ar);
                }
                finally
                {
                    waitHandle.Set();
                }
            }, testObject);

            waitHandle.WaitOne(10000);

            Assert.IsNotNull(pubFile, "Publications file should not be null.");
            Assert.AreEqual(true, isAsyncCorrect, "Unexpected async state.");
        }
    }
}