using System;
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Properties;
using NUnit.Framework;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture]
    public class SignaturePublicationRecordExistenceRuleTests
    {
        [Test]
        public void TestVerify()
        {
            var rule = new SignaturePublicationRecordExistenceRule();

            // Argument null exception when no context
            Assert.Throws<KsiException>(delegate
            {
                rule.Verify(null);
            });

            // Verification exception on missing KSI signature
            Assert.Throws<KsiVerificationException>(delegate
            {
                var context = new TestVerificationContext();

                rule.Verify(context);
            });

            // Check legacy signature
            using (var stream = new FileStream(Resources.KsiSignatureDo_Legacy_Ok_With_Publication_Record, FileMode.Open))
            {
                var context = new TestVerificationContext
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                var verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check signature
            using (var stream = new FileStream(Resources.KsiSignatureDo_Ok_With_Publication_Record, FileMode.Open))
            {
                var context = new TestVerificationContext
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                var verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check invalid signature without publication record
            using (var stream = new FileStream(Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                var context = new TestVerificationContext
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                var verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Na, verificationResult.ResultCode);
            }
        }
    }
}