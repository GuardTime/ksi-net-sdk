using System.Net;
using NUnit.Framework;

namespace Guardtime.KSI.Integration
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
                "resources/signature/integration-test-signatures/ok-sig-extended-2014-05-15.ksig:false:Na: : :UserProvidedPublicationVerificationRule".Split(':'));
            new CommonTestExecution().TestExecution(data, "PublicationStringBasedVerificationUsingOldStringPolicy");
        }

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetCalendarBasedVerificationData))]
        public void CalendarBasedVerificationTest(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "CalendarBasedVerificationPolicy");
        }
    }
}
