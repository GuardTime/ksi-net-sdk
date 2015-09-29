using NUnit.Framework;
using Guardtime.KSI.Signature.Verification.Rule;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture()]
    public class UserProvidedPublicationExistenceRuleTests
    {
        [Test()]
        public void TestVerify()
        {
            var rule = new UserProvidedPublicationExistenceRule();

            // Argument null exception when no context
            Assert.Throws<KsiException>(delegate
            {
                rule.Verify(null);
            });

            var context = new TestVerificationContext();
            var verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Na, verificationResult.ResultCode);

            // Publication is set in context
            context.UserPublication =
                new PublicationData(
                    "AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUACP-GOGD6K");
            verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);

        }
    }
}