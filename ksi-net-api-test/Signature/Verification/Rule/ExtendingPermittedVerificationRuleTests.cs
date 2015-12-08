using Guardtime.KSI.Exceptions;
using NUnit.Framework;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture]
    public class ExtendingPermittedVerificationRuleTests
    {
        [Test]
        public void TestVerify()
        {
            ExtendingPermittedVerificationRule rule = new ExtendingPermittedVerificationRule();

            // Argument null exception when no context
            Assert.Throws<KsiException>(delegate
            {
                rule.Verify(null);
            });

            TestVerificationContext context = new TestVerificationContext {IsExtendingAllowed = true};
            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);

            context.IsExtendingAllowed = false;
            verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Na, verificationResult.ResultCode);
        }
    }
}