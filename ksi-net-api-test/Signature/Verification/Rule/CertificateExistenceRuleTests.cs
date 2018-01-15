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
using Guardtime.KSI.Test.Publication;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class CertificateExistenceRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            CertificateExistenceRule rule = new CertificateExistenceRule();

            // Argument null exception when no context
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                rule.Verify(null);
            });
            Assert.AreEqual("context", ex.ParamName);
        }

        [Test]
        public void TestContextMissingSignature()
        {
            CertificateExistenceRule rule = new CertificateExistenceRule();

            // Verification exception on missing KSI signature 
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();

                rule.Verify(context);
            });
            Assert.That(ex.Message, Does.StartWith("Invalid KSI signature in context: null"));
        }

        [Test]
        public void TestSignatureMissingCalendarAuthRecord()
        {
            CertificateExistenceRule rule = new CertificateExistenceRule();

            // Check signature with no calendar authentication record
            using (
                FileStream stream =
                    new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Invalid_Missing_Calendar_Authentication_Record),
                        FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = new TestPublicationsFile()
                };

                KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
                {
                    rule.Verify(context);
                });
                Assert.That(ex.Message, Does.StartWith("Invalid calendar authentication record in signature: null"));
            }
        }

        [Test]
        public void TestRfc3161SignatureWithoutPublicationsFile()
        {
            CertificateExistenceRule rule = new CertificateExistenceRule();

            // Check legacy signature without publications file. 
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Legacy_Ok), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
                {
                    rule.Verify(context);
                });
                Assert.That(ex.Message, Does.StartWith("Invalid publications file in context: null"));
            }
        }

        [Test]
        public void TestRfc3161SignatureWithPublicationsFile()
        {
            CertificateExistenceRule rule = new CertificateExistenceRule();

            // Check legacy signature without publications file.
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Legacy_Ok), FileMode.Open))
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
        public void TestSignatureWithPublicationsFile()
        {
            CertificateExistenceRule rule = new CertificateExistenceRule();

            // Check signature for certificate existence in publications file with given id in calendar authentication record
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok), FileMode.Open))
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
        public void TestSignatureWithPublicationsFileMissingCertificateId()
        {
            CertificateExistenceRule rule = new CertificateExistenceRule();

            // Check invalid signature with invalid certificate id
            using (
                FileStream stream =
                    new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok),
                        FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = new TestPublicationsFile()
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Key01, verificationResult.VerificationError);
            }
        }
    }
}