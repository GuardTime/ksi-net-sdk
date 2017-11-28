/*
 * Copyright 2013-2017 Guardtime, Inc.
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
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Test.Publication;
using Guardtime.KSI.Test.Trust;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class CalendarAuthenticationRecordSignatureVerificationRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            CalendarAuthenticationRecordSignatureVerificationRule rule = new CalendarAuthenticationRecordSignatureVerificationRule();

            // Argument null exception when no context
            Assert.Throws<ArgumentNullException>(delegate
            {
                rule.Verify(null);
            });
        }

        [Test]
        public void TestContextMissingSignature()
        {
            CalendarAuthenticationRecordSignatureVerificationRule rule = new CalendarAuthenticationRecordSignatureVerificationRule();

            // Verification exception on missing KSI signature
            Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();
                rule.Verify(context);
            });
        }

        [Test]
        public void TestSignatureMissingCalendarAuthenticationRecord()
        {
            CalendarAuthenticationRecordSignatureVerificationRule rule = new CalendarAuthenticationRecordSignatureVerificationRule();

            // Check signature with no calendar authentication record
            using (FileStream stream =
                new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok_Missing_Publication_Record_And_Calendar_Authentication_Record),
                    FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = new TestPublicationsFile()
                };

                Assert.Throws<KsiVerificationException>(delegate
                {
                    rule.Verify(context);
                });
            }
        }

        [Test]
        public void TestSignatureWithInvalidCertificateId()
        {
            CalendarAuthenticationRecordSignatureVerificationRule rule = new CalendarAuthenticationRecordSignatureVerificationRule();

            // Check signature with invalid certificate id
            using (FileStream stream =
                new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = new TestPublicationsFile()
                };

                Assert.Throws<KsiVerificationException>(delegate
                {
                    rule.Verify(context);
                });
            }
        }

        [Test]
        public void TestRfc3161SignatureWithoutPublicationFile()
        {
            CalendarAuthenticationRecordSignatureVerificationRule rule = new CalendarAuthenticationRecordSignatureVerificationRule();

            // Check legacy signature to verify calendar authentication record with and without publications file. With publications file should succeed.
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Legacy_Ok), FileMode.Open))
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
        }

        [Test]
        public void TestRfc3161SignatureWithPublicationFile()
        {
            CalendarAuthenticationRecordSignatureVerificationRule rule = new CalendarAuthenticationRecordSignatureVerificationRule();

            // Check legacy signature to verify calendar authentication record with and without publications file. With publications file should succeed.
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Legacy_Ok), FileMode.Open))
            {
                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
                testPublicationsFile.CertificateRecords.Add(
                    new CertificateRecord(new RawTag(0x702, false, false, Base16.Decode(
                        "0104a42c61ad800202ba308202b63082019e020101300d06092a864886f70d01010b05003021310b300906035504031302483131123010060355040a1309477561726474696d65301e170d3132313132363132323530385a170d3134313232363132323530385a3021310b300906035504031302483131123010060355040a1309477561726474696d6530820122300d06092a864886f70d01010105000382010f003082010a0282010100ba8dd3e9bf9a00d013477054d566907c0848c666f5a2c7829681b0156c98906a22f1d9382646b8a6b408bba20436a963e92496f182729052fa4bffdd77b4c1f56e52f63d7624d9f47ac54fe31770e806f40103b4eb5f7f4e95c4e7f863bf9e887dfe1cf7fdae5e6f2a78e76032168c3f83b233bc409ffe44fc1be39c223e1a58afcceea6e6ae3f7c781fe3eade64b81176ea59722f313126be2224e4d2b82691ec14f7c96b8b0b7ac052d5c9686d17890c6499377a21bb7918af29481b6c41f29e26ff624d44ba234f77aea67c75288ff7f936b1ab6b93dfe1cb8eb89e21b25e22967e21305817847baa2483b170b5967b6472f8d88013a8b05199b23daaf6d702030173b3300d06092a864886f70d01010b0500038201010046c7be7e81640ad3b930c4fa8a70374359e8576d435d36b51d6a58c70d1a028a20273576f4294c2b140f95f844bdbaa44d1a372f6507a1c56b6bcd952e193b3ecb01bc4a5a7f43c124c7655081983cfb713840a29e9869577e7f671893a68fe059c85abd1d7d24d3ab1216c855118a9e532c2e2f82ed85bc946e414dcb4c172975b8b95b0552c71812e550b3a44739a940bb919146055fdacdee820315281369d6acadee763ffc454392a54c9a785f9fe28100911ff130abddd71b968e5d3dad1c8e0fbd61ed685f98d0090c761955156d865e970496eff8330e923a65b5f785507caf666f5e5c4667521f8a4bc5692783bad9503eacdc15e9ed9081a695bbb3")))
                    );

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = testPublicationsFile
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestSignatureWithPublicationFile()
        {
            CalendarAuthenticationRecordSignatureVerificationRule rule = new CalendarAuthenticationRecordSignatureVerificationRule();

            // Check signature and verify calendar authentication record
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok), FileMode.Open))
            {
                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
                testPublicationsFile.CertificateRecords.Add(
                    new CertificateRecord(new RawTag(0x702, false, false, Base16.Decode(
                        "0104644C740D800202BA308202B63082019E020101300D06092A864886F70D01010B05003021310B300906035504031302483331123010060355040A1309477561726474696D65301E170D3134313230343039323831315A170D3137303130343039323831315A3021310B300906035504031302483331123010060355040A1309477561726474696D6530820122300D06092A864886F70D01010105000382010F003082010A0282010100B5E6C54A2C1709E8D44C166319C72072FE4282701AFCCF0A336D9FB7732B8A79193CB36FBD2041F4C6496913D3310A60DA5BAE6BA64DB8697D3503D2EF61A33F267F1BCC4F47F79E70B914D665B5295B6DA29632F18EADF1E9B3369B0301FC146458F2BFD0167C98ED5739714687A7910F93AA2D70DE9F70179E8DCB831A626CAEE31DE91F5F5693D86DF9736CC37199A27FCE9B422152C4FC48FF125788972CC17DD79750A811DA3288E872608975EF9E902B334BFF2CD7CB85BB15CCE4E608DAC7E91EF6C9E774F83F6673F328B1C9A303723F3A1B846D11ED6EDE1BF4BB069C4C4C41B76A5037059BD5DA09950F0F01A7CB7A98D36DC606D62FA7EA29076B0203016F97300D06092A864886F70D01010B050003820101002C82652B380E2551F45BD145409E5C0538CE9BE53B6FA7940A8BFD29CAEB9EDA1CD6E79D02AAB417685B837F19FE8FC73DBB07B3C1D5CD69D6A8262B3BD57B029FC21FB7ED7A02231A9E9E82F3C002C6374C0F9DEDDD541D497FC0CC10CB44081E64B5931DFC123C7E073A5656010E70D76BEAAED7785B4C762E595D1D22892C78D3A8354F6DC1C0019F5E04D00B04C1F6A56695E9B3D2D0823571EB4F696700C5450A378A0CD8E2A2B1A62BD40F4C72AE38EC87951E6E574B8F62BB82D16E6EB7A7B90B917AB545209F3656636C01D145CF256C0977547542CEFB0C5C9C88C2525018DA5F0210CEF4CFF5179AE082AA7A2A3E699793FA0421DA8F2D942A4777")))
                    );

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = testPublicationsFile
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestSignatureWithInvalidCalendarAuthenticationRecordSignature()
        {
            CalendarAuthenticationRecordSignatureVerificationRule rule = new CalendarAuthenticationRecordSignatureVerificationRule();

            // Check invalid signature with invalid calendar authentication record signature
            using (FileStream stream =
                new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Invalid_Calendar_Authentication_Record_Invalid_Signature), FileMode.Open))
            {
                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
                testPublicationsFile.CertificateRecords.Add(
                    new CertificateRecord(new RawTag(0x702, false, false, Base16.Decode(
                        "0104c246b139800202ba308202b63082019e020101300d06092a864886f70d01010b05003021310b300906035504031302483331123010060355040a1309477561726474696d65301e170d3132313132363133303031365a170d3134313232363133303031365a3021310b300906035504031302483331123010060355040a1309477561726474696d6530820122300d06092a864886f70d01010105000382010f003082010a0282010100d59264b31f602edb714e006902313742654a0709c38757b10fa95c459b079ad35812d270df023cc551cb9dbe0611b5ac3aafaaf864f2c2fa9a812345bb163795a51400b8aca96068627b620477614040b0c1e209c997af19ecaf41f8d8dcf2bbf029baea8b1f8ddd17aa173f4810d6f0b46ad78fdd123050680a87e499409ef9fcb91ff6188e1b9def09d952160fc3b0ec614fb97aa021f5d3573520f883138b0e8660203e3d1bde777d2da99207592885a9665fbf85fb624c32c3f76341d07630a2a10965919233e45428cc4f791887cfa82819caa85e9fd68de5f2779ba23f84d05fc2acbc04100d306b06cf0315b1652fb30e13333ebef5763dd15d5346d10203010ec9300d06092a864886f70d01010b05000382010100bfc89ef99af615148fbb5c64028a365666d9b92d77a8e0b96f9e1546dfee6d737d22f0decabce66c05925f21483955fdde296ac24909df0a9862e48b94fd04cfd3023bf37f5836a2b046300ae166460d9d892e2531dcc5eb4b16ab7207174c28688e6e685f4c8d58340724a269efb1abac27c7a3b0a285c454dc590d5339e2f7bf737fb19fdcfe9c1577cd196d3228fe4fdd1706d156486e8f743e0c38bff2d95c197480a690555feb85a831ae76edd367c5d063b557ed9487ff6ac83b94999b409b8003856108ad0cb28b2171014ba4785b89f9e7d2fe75721a4ad011dd4f099b1f165d6312b1ad45255ca7ca254b50c330d3b995810194b3620af358215ec6")))
                    );

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = testPublicationsFile
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Key02, verificationResult.VerificationError);
            }
        }

        [Test]
        public void TestSignatureWithNotValidCertAtAggregationTime()
        {
            CalendarAuthenticationRecordSignatureVerificationRule rule = new CalendarAuthenticationRecordSignatureVerificationRule();

            IPublicationsFile pubsFile;
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                pubsFile = new PublicationsFileFactory(new TestPkiTrustProvider()).Create(stream);
            }

            // Check invalid signature with cert that was not valid at aggregation time.
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Invalid_Not_Valid_Cert), FileMode.Open))
            {
                VerificationContext context = new VerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = pubsFile
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Key03, verificationResult.VerificationError);
            }
        }

        /// <summary>
        /// Test with PKCS#7 calendar auth record signature. 
        /// </summary>
        [Test]
        public void TestPkcs7CalendarAuthenticationRecordSignature()
        {
            // valid from 2016.01.01 - 2026.01.01
            string encodedCert =
                "308201A730820110A003020102021000E5DF21B660FDA6C8B9CDB383DF1C47300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B0500038181000EDDCA6A89605333686FDC50D86664180F15979768BD9FC22742BAEA3355D589F021226DB5D3445C9C41B5376C6180276970D5502A9101D1342A310C4C6EFA33E1747D19D42D405937E922BFFBD2B29A3A13AD884C24802857059B0F92DF840652EF608293EFA09DBD0FCF584B6E271E4B481DD4E6CA74241B63C7A7B2C57E86";
            byte[] certId = new byte[] { 1, 2, 3 };

            CalendarAuthenticationRecordSignatureVerificationRule rule = new CalendarAuthenticationRecordSignatureVerificationRule();

            // Check signature and verify calendar authentication record
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok_Calendar_Auth_Record_Pkcs7_Signature), FileMode.Open))
            {
                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
                testPublicationsFile.CertificateRecords.Add(GetCertificateRecord(certId, Base16.Decode(encodedCert)));

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = testPublicationsFile
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        /// <summary>
        /// Test with PKCS#7 calendar auth record signature. Signed bytes and signature does not match
        /// </summary>
        [Test]
        public void TestWithInvalidPkcs7CalendarAuthenticationRecordSignature()
        {
            // valid from 2016.01.01 - 2026.01.01
            string encodedCert =
                "308201A730820110A003020102021000F8E5378C0921B3E4729551F1ED8819300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B0500038181007949A893A98EA5CF5902B75B62F8DD9219387B7E9BB10A563E85D6176C0E4DF11E9AE76E74F9445EA2B753C9B624AE1C4BBC6F68752E4576A80081C0C2EB9DFD54AEE82557E6FF67A6877FCC911CA86CE7A1051893F193B7E7CD893EEC54BDE8191696A90AC5645615C6AC9BAADF20E736F5B7BBFFBE0125A4B2C6E9020BCDCF";
            byte[] certId = new byte[] { 1, 2, 3 };

            CalendarAuthenticationRecordSignatureVerificationRule rule = new CalendarAuthenticationRecordSignatureVerificationRule();

            // Check signature and verify calendar authentication record
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Invalid_Calendar_Auth_Record_Pkcs7_Signature), FileMode.Open))
            {
                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
                testPublicationsFile.CertificateRecords.Add(GetCertificateRecord(certId, Base16.Decode(encodedCert)));

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = testPublicationsFile
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Key02, verificationResult.VerificationError);
            }
        }

        /// <summary>
        /// Test with PKCS#7 calendar auth record signature. Signature bytes modified.
        /// </summary>
        [Test]
        public void TestWithInvalidPkcs7CalendarAuthenticationRecordSignatureModifiedBytes()
        {
            // valid from 2016.01.01 - 2026.01.01
            string encodedCert =
                "308201A730820110A003020102021000F8E5378C0921B3E4729551F1ED8819300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B0500038181007949A893A98EA5CF5902B75B62F8DD9219387B7E9BB10A563E85D6176C0E4DF11E9AE76E74F9445EA2B753C9B624AE1C4BBC6F68752E4576A80081C0C2EB9DFD54AEE82557E6FF67A6877FCC911CA86CE7A1051893F193B7E7CD893EEC54BDE8191696A90AC5645615C6AC9BAADF20E736F5B7BBFFBE0125A4B2C6E9020BCDCF";
            byte[] certId = new byte[] { 1, 2, 3 };

            CalendarAuthenticationRecordSignatureVerificationRule rule = new CalendarAuthenticationRecordSignatureVerificationRule();

            // Check signature and verify calendar authentication record
            using (
                FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Invalid_Calendar_Auth_Record_Pkcs7_Signature_Modified_Bytes),
                    FileMode.Open))
            {
                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
                testPublicationsFile.CertificateRecords.Add(GetCertificateRecord(certId, Base16.Decode(encodedCert)));

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = testPublicationsFile
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Key02, verificationResult.VerificationError);
            }
        }

        /// <summary>
        /// Test with PKCS#7 calendar auth record signature. Signature and certificate do not match.
        /// </summary>
        [Test]
        public void TestWithInvalidPkcs7CalendarAuthenticationRecordSignatureCert()
        {
            // invalid cert

            string encodedCert =
                "308201A730820110A003020102021000A23595D54EC5CD4CE4B2C442054819300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100A75F9454CDE6E398DC17C0A34B50CFA522BCAB28BA492087C609B295BD93159A82F4ED6225A1C424FB4DE3C5D871CADA882BC7764BAFD86484C06FB582E66CF229D1B7722C847E7803C5C682C9ADBEEBE924D8402CF0464DBE34D1DAF6F319689F730ECF002298FEEB31537FBE3C5276B399DAB4441DD456200800FF6A8263310203010001300D06092A864886F70D01010B05000381810005E41DAD3113FA3F650F0D26B341022FC586C7ACC584E9B32A586EF4E1D02C84099773F8957AD5FC6971C732194047F5A0302D19A47A478B14D43FDB5838CEFEE55F55432BC86C61E76297865CBBFAA13A436585B222441D51236879FD33EBC35FFCADBE9450CEAE60AC487626732248BEF0093D45C10AF634277D8C0791E68A";
            byte[] certId = new byte[] { 1, 2, 3 };

            CalendarAuthenticationRecordSignatureVerificationRule rule = new CalendarAuthenticationRecordSignatureVerificationRule();

            // Check signature and verify calendar authentication record
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok_Calendar_Auth_Record_Pkcs7_Signature), FileMode.Open))
            {
                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
                testPublicationsFile.CertificateRecords.Add(GetCertificateRecord(certId, Base16.Decode(encodedCert)));

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = testPublicationsFile
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Key02, verificationResult.VerificationError);
            }
        }

        /// <summary>
        /// Test with PKCS#7 calendar auth record signature. Certificate not valid at aggregation time.
        /// </summary>
        [Test]
        public void TestWithPkcs7NotValidCertAtAggregationTime()
        {
            // valid from 2017.01.01 - 2026.01.01
            string encodedCert =
                "308201A730820110A003020102021000E919B09EB95329A7256DBE49C9BB63300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3137303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B0500038181004BBD34640D7AD7E38C50BDB72D374EBB9065241CE564A9431B18CBF45AFBFB933B151F6D4B4B1142A72B9420F0491D5CFC414B9AFAB11465AC23D48749114E12B8FE0A1F71C272C40BF2A2CCC51895A413CE79019ABDB46FBE8AC5EA2C69C4C801C70D63BFA1F27D77908238825773967552155AA79FEAFC595D7BD6F5BFFA02";
            byte[] certId = new byte[] { 1, 2, 3 };

            CalendarAuthenticationRecordSignatureVerificationRule rule = new CalendarAuthenticationRecordSignatureVerificationRule();

            // Check signature and verify calendar authentication record
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath,
                Resources.KsiSignature_Invalid_Calendar_Auth_Record_Pkcs7_Signature_Not_Valid_Cert), FileMode.Open))
            {
                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
                testPublicationsFile.CertificateRecords.Add(GetCertificateRecord(certId, Base16.Decode(encodedCert)));

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = testPublicationsFile
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Key03, verificationResult.VerificationError);
            }
        }

        private CertificateRecord GetCertificateRecord(byte[] id, byte[] cert)
        {
            byte[] idTagBytes = new RawTag(Constants.CertificateRecord.CertificateIdTagType, false, false, id).Encode();
            byte[] certTagBytes = new RawTag(Constants.CertificateRecord.X509CertificateTagType, false, false, cert).Encode();

            MemoryStream stream = new MemoryStream();

            stream.Write(idTagBytes, 0, idTagBytes.Length);
            stream.Write(certTagBytes, 0, certTagBytes.Length);

            return new CertificateRecord(new RawTag(Constants.CertificateRecord.TagType, false, false, stream.ToArray()));
        }
    }
}