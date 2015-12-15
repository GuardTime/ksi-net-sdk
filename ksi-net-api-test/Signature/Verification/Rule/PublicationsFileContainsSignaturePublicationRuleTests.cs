using System.IO;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Trust;
using NUnit.Framework;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture]
    public class PublicationsFileContainsSignaturePublicationRuleTests
    {
        [Test]
        public void TestVerify()
        {
            PublicationsFileContainsSignaturePublicationRule rule = new PublicationsFileContainsSignaturePublicationRule();

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

            // No publications file defined
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                Assert.Throws<KsiVerificationException>(delegate
                {
                    rule.Verify(context);
                });
            }

            IPublicationsFile publicationsFile;
            using (FileStream stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                publicationsFile =
                    new PublicationsFileFactory(new PkiTrustStoreProvider(TrustStoreUtilities.GetTrustAnchorCollection(),
                        new CertificateSubjectRdnSelector("E=publications@guardtime.com"))).Create(stream);
            }

            // Check signature with not publications record
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                TestVerificationContextFaultyFunctions context = new TestVerificationContextFaultyFunctions()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = publicationsFile
                };

                Assert.Throws<KsiVerificationException>(delegate
                {
                    rule.Verify(context);
                });
            }

            // Check legacy signature
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Legacy_Ok_With_Publication_Record, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = publicationsFile
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check signature
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_With_Publication_Record, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = publicationsFile
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check invalid signature with publication record missing from publications file
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Invalid_With_Invalid_Publication_Record, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = publicationsFile
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Na, verificationResult.ResultCode);
            }
        }
    }
}