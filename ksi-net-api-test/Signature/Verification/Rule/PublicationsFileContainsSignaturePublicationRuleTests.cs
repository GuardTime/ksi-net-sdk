using NUnit.Framework;
using Guardtime.KSI.Signature.Verification.Rule;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Trust;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture()]
    public class PublicationsFileContainsSignaturePublicationRuleTests
    {
        [Test()]
        public void TestVerify()
        {
            var rule = new PublicationsFileContainsSignaturePublicationRule();

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

            // No publications file defined
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                Assert.Throws<KsiVerificationException>(delegate
                {
                    rule.Verify(context);
                });
            }

            IPublicationsFile publicationsFile;
            using (var stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                publicationsFile = new PublicationsFileFactory(new PkiTrustStoreProvider()).Create(stream);
            }

            // Check signature with not publications record
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                var context = new TestVerificationContextFaultyFunctions()
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
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Legacy_Ok_With_Publication_Record, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = publicationsFile
                };

                var verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check signature
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_With_Publication_Record, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = publicationsFile
                };

                var verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check invalid signature with publication record missing from publications file
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Invalid_With_Invalid_Publication_Record, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = publicationsFile
                };

                var verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Na, verificationResult.ResultCode);
            }
        }
    }
}