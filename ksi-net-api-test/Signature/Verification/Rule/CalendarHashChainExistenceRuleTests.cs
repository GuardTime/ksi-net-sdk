using NUnit.Framework;
using System.IO;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture]
    public class CalendarHashChainExistenceRuleTests
    {
        [Test]
        public void TestVerify()
        {
            CalendarHashChainExistenceRule rule = new CalendarHashChainExistenceRule();

            // Argument null exception when no context
            Assert.Throws<KsiException>(delegate
            {
                rule.Verify(null);
            });

            // Verification exception on missing KSI signature 
            Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();

                rule.Verify(context);
            });

            // check signature for calendar hash chain
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check signature which has not calendar hash chain
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_Missing_Calendar_Hash_Chain, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Na, verificationResult.ResultCode);
            }
        }
    }
}