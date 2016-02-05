using System.IO;
using System.Text;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Trust;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Integration
{
    [TestFixture]
    public class ExtendIntegrationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TestCases))]
        public void ExtendToHeadAndVerifyUserProvidedPublicationTest(Ksi ksi)
        {
            UserProvidedPublicationVerificationRule rule = new UserProvidedPublicationVerificationRule();

            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_With_Publication_Record, FileMode.Open))
            {
                PublicationData publicationData = ksi.GetPublicationsFile().GetLatestPublication().PublicationData;

                IKsiSignature ksiSignature = new KsiSignatureFactory().Create(stream);
                IKsiSignature extendedSignature = ksi.ExtendToHead(ksiSignature);

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = extendedSignature,
                    UserPublication = publicationData
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TestCases))]
        public void ExtendAndVerifyToUserProvidedPublicationTest(Ksi ksi)
        {
            UserProvidedPublicationVerificationRule rule = new UserProvidedPublicationVerificationRule();

            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_With_Publication_Record, FileMode.Open))
            {
                PublicationData publicationData = new PublicationData("AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUACP-GOGD6K");

                IKsiSignature ksiSignature = new KsiSignatureFactory().Create(stream);
                IKsiSignature extendedSignature = ksi.Extend(ksiSignature, publicationData);

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = extendedSignature,
                    UserPublication = publicationData
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TestCases))]
        public void InvalidExtendToUserProvidedPublicationTest(Ksi ksi)
        {
            UserProvidedPublicationVerificationRule rule = new UserProvidedPublicationVerificationRule();

            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_With_Publication_Record, FileMode.Open))
            {
                // publication data with modified hash
                PublicationData publicationData = new PublicationData("AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUBD7-OE44VA");

                IKsiSignature ksiSignature = new KsiSignatureFactory().Create(stream);
                IKsiSignature extendedSignature = ksi.Extend(ksiSignature, publicationData);

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = extendedSignature,
                    UserPublication = publicationData
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Na, verificationResult.ResultCode);
            }
        }
    }
}