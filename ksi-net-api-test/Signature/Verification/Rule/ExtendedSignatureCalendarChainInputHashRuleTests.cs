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

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture()]
    public class ExtendedSignatureCalendarChainInputHashRuleTests
    {
        [Test()]
        public void TestVerify()
        {
            var rule = new ExtendedSignatureCalendarChainInputHashRule();

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

            var serviceProtocol = new TestKsiServiceProtocol();
            var ksiService = new KsiService(serviceProtocol, serviceProtocol, serviceProtocol, new ServiceCredentials("anon", "anon"), new PublicationsFileFactory());

            // Check signature without calendar chain
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_Missing_Calendar_Hash_Chain, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = KsiSignature.GetInstance(stream),
                    KsiService = ksiService
                };

                rule.Verify(context);
            }

            // Check invalid extended calendar chain with faulty context functions
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                var context = new TestVerificationContextFaultyFunctions()
                {
                    Signature = KsiSignature.GetInstance(stream),
                    KsiService = ksiService
                };

                Assert.Throws<KsiVerificationException>(delegate
                {
                    rule.Verify(context);
                });
            }

            // Check legacy signature
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Legacy_Ok, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = KsiSignature.GetInstance(stream),
                    KsiService = ksiService
                };

                Assert.AreEqual(VerificationResult.Ok, rule.Verify(context));
            }

            // Check signature
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = KsiSignature.GetInstance(stream),
                    KsiService = ksiService
                };

                Assert.AreEqual(VerificationResult.Ok, rule.Verify(context));
            }

            // Check invalid signature extended calendar hash chain input hash
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Invalid_With_Invalid_Aggregation_Root_Hash, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = KsiSignature.GetInstance(stream),
                    KsiService = ksiService
                };

                Assert.AreEqual(VerificationResult.Fail, rule.Verify(context));
            }
        }
    }
}