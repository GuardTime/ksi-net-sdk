using System.IO;
using Guardtime.KSI.Exceptions;
using NUnit.Framework;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture]
    public class CalendarAuthenticationRecordAggregationHashRuleTests
    {
        [Test]
        public void TestVerify()
        {
            CalendarAuthenticationRecordAggregationHashRule rule = new CalendarAuthenticationRecordAggregationHashRule();

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

            // Check legacy signature for missing calendar hash chain and existing calendar authentication record
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Legacy_Ok, FileMode.Open))
            {
                Assert.Throws<KsiVerificationException>(delegate
                {
                    IKsiSignature signature = new KsiSignatureFactory().Create(stream);
                    TestVerificationContext context = new TestVerificationContext()
                    {
                        Signature = new TestKsiSignature()
                        {
                            CalendarAuthenticationRecord = signature.CalendarAuthenticationRecord
                        }
                    };

                    rule.Verify(context);
                });
            }

            // Check legacy signature for calendar authentication record hash
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Legacy_Ok, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check signature for calendar authentication record hash
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check signature with no calendar authentication record
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_Missing_Publication_Record_And_Calendar_Authentication_Record, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check invalid signature with invalid publication hash in calendar authentication record
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Invalid_Calendar_Authentication_Record_Invalid_Publication_Hash, FileMode.Open))
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