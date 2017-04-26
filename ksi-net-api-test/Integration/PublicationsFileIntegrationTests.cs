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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Integration
{
    public class PublicationsFileIntegrationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void GetPublicationsFileTest(Ksi ksi)
        {
            IPublicationsFile publicationsFile = ksi.GetPublicationsFile();

            PublicationRecordInPublicationFile latest = publicationsFile.GetLatestPublication();
            if (latest == null)
            {
                Assert.True(true);
                return;
            }

            PublicationRecordInPublicationFile prev = publicationsFile.GetNearestPublicationRecord(latest.PublicationData.PublicationTime - 35 * 24 * 3600);

            Assert.True(latest.PublicationData.PublicationTime > prev.PublicationData.PublicationTime);

            prev = publicationsFile.GetNearestPublicationRecord(Util.ConvertUnixTimeToDateTime(latest.PublicationData.PublicationTime).AddDays(-35));

            Assert.True(latest.PublicationData.PublicationTime > prev.PublicationData.PublicationTime);
        }

        [Test]
        public void EndGetPublicationsFileArgumentNullTest()
        {
            KsiService service = GetHttpKsiService();

            Assert.Throws<ArgumentNullException>(delegate
            {
                service.EndGetPublicationsFile(null);
            });
        }

        [Test]
        public void EndGetPublicationsFileInvalidArgumentTest()
        {
            KsiService service = GetHttpKsiService();

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.EndGetPublicationsFile(new TestAsyncResult());
            });

            Assert.That(ex.Message.StartsWith("Invalid asyncResult, could not cast to correct object."), "Unexpected exception message: " + ex.Message);
        }
    }
}