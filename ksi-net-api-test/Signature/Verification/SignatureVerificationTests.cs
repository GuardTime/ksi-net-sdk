/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Properties;
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
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok), FileMode.Open))
            {
                HttpKsiServiceProtocol serviceProtocol = new HttpKsiServiceProtocol(
                    Settings.Default.HttpSigningServiceUrl,
                    Settings.Default.HttpExtendingServiceUrl,
                    Settings.Default.HttpPublicationsFileUrl);

                KsiService ksiService = new KsiService(
                    serviceProtocol, new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass),
                    serviceProtocol, new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass),
                    serviceProtocol,
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
                                new FileStream(Path.Combine(TestSetup.LocalPath, "resources/publication/publicationsfile/ksi-publications.bin"), FileMode.Open))
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

                Console.WriteLine(policy.Verify(context));

                Console.WriteLine(@"// Calendar based verification");
                policy = new CalendarBasedVerificationPolicy();
                Console.WriteLine(policy.Verify(context));
            }
        }
    }
}