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
    public class CalendarAuthenticationRecordAggregationHashRuleTests
    {
        [Test()]
        public void TestVerify()
        {
            var rule = new CalendarAuthenticationRecordAggregationHashRule();

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

            // Check legacy signature for calendar authentication record hash
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Legacy_Ok, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                Assert.AreEqual(VerificationResult.Ok, rule.Verify(context));
            }

            // Check signature for calendar authentication record hash
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                Assert.AreEqual(VerificationResult.Ok, rule.Verify(context));
            }

            // Check signature with no calendar authentication record
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_Missing_Publication_Record_And_Calendar_Authentication_Record, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                Assert.AreEqual(VerificationResult.Ok, rule.Verify(context));
            }

            // Check invalid signature with invalid publication hash in calendar authentication record
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Invalid_Calendar_Authentication_Record_Invalid_Publication_Hash, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                Assert.AreEqual(VerificationResult.Fail, rule.Verify(context));
            }
        }
    }
}