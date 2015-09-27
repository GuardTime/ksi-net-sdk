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
using Guardtime.KSI.Service;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture()]
    public class ExtendingPermittedVerificationRuleTests
    {
        [Test()]
        public void TestVerify()
        {
            var rule = new ExtendingPermittedVerificationRule();

            // Argument null exception when no context
            Assert.Throws<KsiException>(delegate
            {
                rule.Verify(null);
            });

            var context = new TestVerificationContext {IsExtendingAllowed = true};
            Assert.AreEqual(VerificationResult.Ok, rule.Verify(context));

            context.IsExtendingAllowed = false;
            Assert.AreEqual(VerificationResult.Na, rule.Verify(context));
        }
    }
}