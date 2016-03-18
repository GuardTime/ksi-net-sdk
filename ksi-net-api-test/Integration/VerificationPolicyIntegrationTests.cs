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

using NUnit.Framework;

namespace Guardtime.KSI.Test.Integration
{
    [TestFixture]
    public class VerificationPolicyIntegrationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetKeyBasedVerificationData))]
        public void KeyBasedVerificationTest(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "KeyBasedVerificationPolicy");
        }

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetKeyBasedVerificationDataWithNoPublication))]
        public void KeyBasedVerificationTestWithNoPublication(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "KeyBasedVerificationPolicyWithNoPublication");
        }

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetPublicationFileBasedVerificationData))]
        public void PublicationFileBasedVerificationTest(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "PublicationFileBasedVerificationPolicy");
        }

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetPublicationFileBasedVerificationNoExtendingData))]
        public void PublicationFileBasedVerificationNoExtendingTest(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "PublicationFileBasedVerificationNoExtendingPolicy");
        }

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetPublicationStringVerificationData))]
        public void PublicationStringBasedVerificationTest(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "PublicationStringBasedVerificationPolicy");
        }

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetPublicationStringVerificationNoExtendingData))]
        public void PublicationStringBasedVerificationNoExtendingTest(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "PublicationStringBasedVerificationNoExtendingPolicy");
        }

        [Test]
        public void PublicationStringBasedVerificationUsingOldStringTest()
        {
            DataHolderForIntegrationTests data = new DataHolderForIntegrationTests(
                "resources/signature/integration-test-signatures/ok-sig-extended-2014-05-15.ksig:false:Na: : :UserProvidedPublicationCreationTimeVerificationRule".Split(':'));
            new CommonTestExecution().TestExecution(data, "PublicationStringBasedVerificationUsingOldStringPolicy");
        }

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetCalendarBasedVerificationData))]
        public void CalendarBasedVerificationTest(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "CalendarBasedVerificationPolicy");
        }
    }
}