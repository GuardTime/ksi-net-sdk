using NUnit.Framework;
using System.IO;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture]
    public class SignaturePublicationRecordPublicationHashRuleTests
    {
        [Test]
        public void TestVerify()
        {
            SignaturePublicationRecordPublicationHashRule rule = new SignaturePublicationRecordPublicationHashRule();

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

            // Check legacy signature for missing calendar hash chain and existing publication record
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_With_Publication_Record, FileMode.Open))
            {
                Assert.Throws<KsiVerificationException>(delegate
                {
                    IKsiSignature signature = new KsiSignatureFactory().Create(stream);
                    TestVerificationContext context = new TestVerificationContext()
                    {
                        Signature = new TestKsiSignature()
                        {
                            PublicationRecord = signature.PublicationRecord
                        }
                    };

                    rule.Verify(context);
                });
            }

            // Check signature without publications record
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check legacy signature with publications record
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Legacy_Ok_With_Publication_Record, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check signature with publications record
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_With_Publication_Record, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check invalid signature with invalid publication record
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Invalid_With_Invalid_Publication_Record, FileMode.Open))
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