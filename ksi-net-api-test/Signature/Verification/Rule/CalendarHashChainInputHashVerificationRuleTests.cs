using NUnit.Framework;
using Guardtime.KSI.Signature.Verification.Rule;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture()]
    public class CalendarHashChainInputHashVerificationRuleTests
    {
        [Test()]
        public void TestVerify()
        {
            var rule = new CalendarHashChainInputHashVerificationRule();

            // Argument null exception when no context
            Assert.Throws<ArgumentNullException>(delegate
            {
                rule.Verify(null);
            });

            // Verification exception on missing KSI signature 
            Assert.Throws<KsiVerificationException>(delegate
            {
                var context = new TestVerificationContext();

                rule.Verify(context);
            });

            // Check legacy signature calendar hash chain input hash
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Legacy_Ok, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = KsiSignature.GetInstance(stream)
                };

                Assert.AreEqual(VerificationResult.Ok, rule.Verify(context));
            }

            // Check signature calendar hash chain input hash
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = KsiSignature.GetInstance(stream)
                };

                Assert.AreEqual(VerificationResult.Ok, rule.Verify(context));
            }

            // Check signature without calendar chain
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_Missing_Calendar_Hash_Chain, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = KsiSignature.GetInstance(stream)
                };

                Assert.AreEqual(VerificationResult.Ok, rule.Verify(context));
            }

            // Check invalid signature with invalid calendar chain input hash
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Invalid_Calendar_Chain_Input_Hash, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = KsiSignature.GetInstance(stream)
                };

                Assert.AreEqual(VerificationResult.Fail, rule.Verify(context));
            }
        }
    }
}