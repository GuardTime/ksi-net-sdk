using System.IO;
using System.Text;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Integration
{
    [TestFixture]
    public class SignIntegrationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof (IntegrationTests), "TestCases")]
        public void SignHashTest(Ksi ksi)
        {
            var signature = ksi.Sign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
            var verificationContext = new VerificationContext(signature)
            {
                DocumentHash = new DataHash(HashAlgorithm.Sha2256,
                    Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")),
                PublicationsFile = ksi.GetPublicationsFile()
            };
            var verificationResult = ksi.Verify(verificationContext, new KeyBasedVerificationPolicy());
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode, "Signature should verify with key based policy");
        }

        [Test, TestCaseSource(typeof (IntegrationTests), "TestCases")]
        public void SignedHashVerifyWithInvalidHashTest(Ksi ksi)
        {
            using (var memoryStream = new MemoryStream(Encoding.UTF8.GetBytes("test")))
            {
                var dataHasher = new DataHasher(HashAlgorithm.Sha2256);
                dataHasher.AddData(memoryStream);
                var signature = ksi.Sign(dataHasher.GetHash());

                var verificationContext = new VerificationContext(signature)
                {
                    DocumentHash = new DataHash(HashAlgorithm.Sha2256,
                        Base16.Decode("1f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")),
                    PublicationsFile = ksi.GetPublicationsFile()
                };
                var verificationResult = ksi.Verify(verificationContext, new KeyBasedVerificationPolicy());
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode, "Signature should verify with key based policy");
            }
        }
    }
}