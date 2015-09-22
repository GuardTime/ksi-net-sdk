using System;
using System.IO;
using NUnit.Framework;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    // Better name for ruletests
    [TestFixture]
    public class AggregationChainInputHashVerificationVerificationRuleTests
    {
        [Test]
        public void TestVerify()
        {
            var rule = new AggregationChainInputHashVerificationRule();
            Assert.Throws<ArgumentNullException>(delegate
            {
                rule.Verify(null);
            });

            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = KsiSignature.GetInstance(stream)
                };

                rule.Verify(context);
            }
        }
    }
}