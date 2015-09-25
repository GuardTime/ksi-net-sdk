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

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture()]
    public class CertificateExistenceRuleTests
    {
        [Test()]
        public void TestVerify()
        {
            var rule = new CertificateExistenceRule();

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

            IPublicationsFile publicationsFile;
            using (var stream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
            {
                publicationsFile = new PublicationsFileFactory().Create(stream);
            }

            // Check signature with no calendar authentication record
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_Missing_Publication_Record_And_Calendar_Authentication_Record, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = publicationsFile
                };

                Assert.Throws<KsiVerificationException>(delegate
                {
                    rule.Verify(context);
                });
            }

            // Check legacy signature with and without publications file. With publications file succeeds.
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Legacy_Ok, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                Assert.Throws<KsiVerificationException>(delegate
                {
                    rule.Verify(context);
                });

                context.PublicationsFile = publicationsFile;

                Assert.AreEqual(VerificationResult.Ok, rule.Verify(context));
            }

            // Check signature for certificate existence in publications file with given id in calendar authentication record
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = publicationsFile
                };

                Assert.AreEqual(VerificationResult.Ok, rule.Verify(context));
            }

            // Check invalid signature with invalid certificate id
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Invalid_Calendar_Authentication_Record_Invalid_Certificate_Id, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = publicationsFile
                };

                Assert.AreEqual(VerificationResult.Fail, rule.Verify(context));
            }
        }
    }
}