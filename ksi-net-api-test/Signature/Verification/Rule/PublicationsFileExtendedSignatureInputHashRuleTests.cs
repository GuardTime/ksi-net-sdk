using NUnit.Framework;
using Guardtime.KSI.Signature.Verification.Rule;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Trust;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture()]
    public class PublicationsFileExtendedSignatureInputHashRuleTests
    {
        [Test()]
        public void TestVerify()
        {
            var rule = new PublicationsFileExtendedSignatureInputHashRule();

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

            // Invalid publications file in context: null
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

            // Check invalid publications record in signature: null
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_Missing_Calendar_Hash_Chain, FileMode.Open))
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

            var serviceProtocol = new TestKsiServiceProtocol();
            var ksiService = new KsiService(serviceProtocol, serviceProtocol, serviceProtocol, new ServiceCredentials("anon", "anon"), new PublicationsFileFactory(new PkiTrustStoreProvider()), new KsiSignatureFactory());
            
            
            // Check invalid extended calendar chain from context function: null
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                var context = new TestVerificationContextFaultyFunctions()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = publicationsFile,
                    KsiService = ksiService
                };

                Assert.Throws<KsiVerificationException>(delegate
                {
                    rule.Verify(context);
                });
            }

            // Check no publication found after current signature
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_New, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = publicationsFile,
                    KsiService = ksiService
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
                    PublicationsFile = publicationsFile,
                    KsiService = ksiService
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
                    PublicationsFile = publicationsFile,
                    KsiService = ksiService
                };

                var verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check invalid signature
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Invalid_With_Invalid_Publication_Record, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = publicationsFile,
                    KsiService = ksiService
                };

                var verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
            }
        }
    }
}