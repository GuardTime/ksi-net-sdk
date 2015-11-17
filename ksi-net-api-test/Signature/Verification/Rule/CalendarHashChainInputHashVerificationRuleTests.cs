using NUnit.Framework;
using System.IO;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture]
    public class CalendarHashChainInputHashVerificationRuleTests
    {
        [Test]
        public void TestVerify()
        {
            CalendarHashChainInputHashVerificationRule rule = new CalendarHashChainInputHashVerificationRule();

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

            // Check legacy signature calendar hash chain input hash
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Legacy_Ok, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check signature calendar hash chain input hash
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check signature without calendar chain
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_Missing_Calendar_Hash_Chain, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check invalid signature with invalid calendar chain input hash
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Invalid_Calendar_Chain_Input_Hash, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
            }
        }
    }
}