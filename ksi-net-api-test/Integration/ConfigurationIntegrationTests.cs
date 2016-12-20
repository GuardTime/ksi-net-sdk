using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Service;
using NUnit.Framework;
using System;

namespace Guardtime.KSI.Test.Integration
{
    [TestFixture]
    public class ConfigurationIntegrationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void GetAggregatorConfigTest(Ksi ksi)
        {
            if (TestSetup.PduVersion == PduVersion.v1)
            {
                Exception ex = Assert.Throws<KsiServiceException>(delegate
                {
                    ksi.GetAggregatorConfig();
                });

                Assert.That(ex.Message.StartsWith("Aggregator config request is not supported using PDU version v1"), "Unexpected exception message: " + ex.Message);
            }
            else
            {
                ksi.GetAggregatorConfig();
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidExtendingUrl))]
        public void GetAggregatorConfigSuccessWithInvalidSigningUrlTest(Ksi ksi)
        {
            if (TestSetup.PduVersion != PduVersion.v1)
            {
                Assert.DoesNotThrow(delegate
                {
                    ksi.GetAggregatorConfig();
                }, "Invalid extending url should not prevent getting aggregator config.");
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidExtendingPass))]
        public void GetAggregatorConfigSuccessWithInvalidSigningPassTest(Ksi ksi)
        {
            if (TestSetup.PduVersion != PduVersion.v1)
            {
                Assert.DoesNotThrow(delegate
                {
                    ksi.GetAggregatorConfig();
                }, "Invalid extending password should not prevent getting aggregator config.");
            }
        }



        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void GetExtenderConfig(Ksi ksi)
        {
            if (TestSetup.PduVersion == PduVersion.v1)
            {
                Exception ex = Assert.Throws<KsiServiceException>(delegate
                {
                    ksi.GetExtenderConfig();
                });

                Assert.That(ex.Message.StartsWith("Extender config request is not supported using PDU version v1"), "Unexpected exception message: " + ex.Message);
            }
            else
            {
                ksi.GetExtenderConfig();
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidSigningUrl))]
        public void GetExtenderConfigSuccessWithInvalidSigningUrlTest(Ksi ksi)
        {
            if (TestSetup.PduVersion != PduVersion.v1)
            {
                Assert.DoesNotThrow(delegate
                {
                    ksi.GetExtenderConfig();
                }, "Invalid signing url should not prevent getting extnder config.");
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidSigningPass))]
        public void GetExtenderConfigSuccessWithInvalidSigningPassTest(Ksi ksi)
        {
            if (TestSetup.PduVersion != PduVersion.v1)
            {
                Assert.DoesNotThrow(delegate
                {
                    ksi.GetExtenderConfig();
                }, "Invalid signing password should not prevent getting extnder config.");
            }
        }
    }
}
