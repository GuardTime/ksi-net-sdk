﻿using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Signature.Verification.Policy;
using NUnit.Framework;

namespace Guardtime.KSI.Integration
{
    [TestFixture]
    public class InternalVerificationTests : IntegrationTests
    {

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetKeyBasedVerificationData))]
        public void KeyBasedVerificationTest(DataHolderForIntegrationTests data)
        {
            new WebClient().DownloadFile("http://verify.guardtime.com/ksi-publications.bin", "resources/publication/publicationsfile/newest-ksi-publications.bin");
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
            new WebClient().DownloadFile("http://verify.guardtime.com/ksi-publications.bin", "resources/publication/publicationsfile/newest-ksi-publications.bin");
            new CommonTestExecution().TestExecution(data, "PublicationFileBasedVerificationPolicy");
        }

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetPublicationStringVerificationData))]
        public void PublicationStringBasedVerificationTest(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "PublicationStringBasedVerificationPolicy");
        }

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetCalendarBasedVerificationData))]
        public void CalendarBasedVerificationTest(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "CalendarBasedVerificationPolicy");
        }
    }
}
