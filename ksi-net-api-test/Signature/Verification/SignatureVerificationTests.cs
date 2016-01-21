using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Trust;
using NUnit.Framework;

namespace Guardtime.KSI.Signature.Verification
{
    [TestFixture]
    public class SignatureVerificationTests
    {
        [Test]
        public void TestVerifySignatureOk()
        {
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                HttpKsiServiceProtocol serviceProtocol = new HttpKsiServiceProtocol(
                    "http://ksigw.test.guardtime.com:3333/gt-signingservice",
                    "http://172.20.20.100:8081",
                    "http://verify.guardtime.com/ksi-publications.bin");

                KsiService ksiService = new KsiService(serviceProtocol, serviceProtocol, serviceProtocol, new ServiceCredentials("anon", "anon"),
                    new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        new CertificateSubjectRdnSelector("E=publications@guardtime.com"))), new KsiSignatureFactory());
                VerificationContext context = new VerificationContext(new KsiSignatureFactory().Create(stream))
                {
                    DocumentHash =
                        new Hashing.DataHash(new byte[]
                        {
                            0x01, 0x11, 0xA7, 0x00, 0xB0, 0xC8, 0x06, 0x6C, 0x47, 0xEC, 0xBA, 0x05, 0xED, 0x37, 0xBC,
                            0x14,
                            0xDC, 0xAD, 0xB2, 0x38, 0x55, 0x2D, 0x86, 0xC6, 0x59, 0x34, 0x2D, 0x1D, 0x7E, 0x87, 0xB8,
                            0x77, 0x2D
                        }),
                    //UserPublication = new PublicationData("AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUACP-GOGD6K"),
                    IsExtendingAllowed = true,
                    KsiService = ksiService,
                    PublicationsFile =
                        new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                            new CertificateSubjectRdnSelector(new List<CertificateSubjectRdn> { new CertificateSubjectRdn("1.2.840.113549.1.9.1", "publications@guardtime.com") })))
                            .Create(
                                new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
                };

                Console.WriteLine(@"// Internal verification policy");
                VerificationPolicy policy = new InternalVerificationPolicy();
                Console.WriteLine(policy.Verify(context));

                Console.WriteLine(@"// Publications based");
                policy = new PublicationBasedVerificationPolicy();
                Console.WriteLine(policy.Verify(context));

                Console.WriteLine(@"// Key based");
                policy = new KeyBasedVerificationPolicy(new X509Store(StoreName.Root),
                    new CertificateSubjectRdnSelector(new List<CertificateSubjectRdn> { new CertificateSubjectRdn("1.2.840.113549.1.9.1", "publications@guardtime.com") }));
                ;
                Console.WriteLine(policy.Verify(context));

                Console.WriteLine(@"// Calendar based verification");
                policy = new CalendarBasedVerificationPolicy();
                Console.WriteLine(policy.Verify(context));
            }
        }
    }
}