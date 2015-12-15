using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    // Better name for ruletests
    [TestFixture]
    public class AggregationChainInputHashVerificationRuleTests
    {
        [Test]
        public void TestVerify()
        {
            AggregationChainInputHashVerificationRule rule = new AggregationChainInputHashVerificationRule();

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

            // Check legacy signature without document hash
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Legacy_Ok, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                Assert.Throws<KsiException>(delegate
                {
                    rule.Verify(context);
                });
            }

            // Check signature without aggregation hash chains
            Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new TestKsiSignature(),
                    DocumentHash =
                        new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"))
                };

                rule.Verify(context);
            });

            // Check legacy signature input hash
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Legacy_Ok, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    DocumentHash =
                        new DataHash(Base16.Decode("015466E3CBA14A843A5E93B78E3D6AB8D3491EDCAC7E06431CE1A7F49828C340C3"))
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check signature input hash
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    DocumentHash =
                        new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"))
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check signature invalid input hash
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    DocumentHash =
                        new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772E"))
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
            }
        }
    }
}