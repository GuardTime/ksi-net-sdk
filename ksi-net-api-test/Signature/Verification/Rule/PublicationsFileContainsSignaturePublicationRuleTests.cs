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
    public class PublicationsFileContainsSignaturePublicationRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            PublicationsFileContainsSignaturePublicationRule rule = new PublicationsFileContainsSignaturePublicationRule();

            // Argument null exception when no context
            Assert.Throws<KsiException>(delegate
            {
                rule.Verify(null);
            });
        }

        [Test]
        public void TestContextMissingSignature()
        {
            PublicationsFileContainsSignaturePublicationRule rule = new PublicationsFileContainsSignaturePublicationRule();

            // Verification exception on missing KSI signature
            Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();

                rule.Verify(context);
            });
        }

        [Test]
        public void TestMissingPublicationsFile()
        {
            PublicationsFileContainsSignaturePublicationRule rule = new PublicationsFileContainsSignaturePublicationRule();

            // No publications file defined
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok), FileMode.Open))
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
        public void TestSignatureWithPublicationsFileMissingPublicationsRecord()
        {
            PublicationsFileContainsSignaturePublicationRule rule = new PublicationsFileContainsSignaturePublicationRule();

            // Check signature with not publications record
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok), FileMode.Open))
            {
                TestVerificationContextFaultyFunctions context = new TestVerificationContextFaultyFunctions()
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
        public void TestRfc3161SignatureWithPublicationsFilePublication()
        {
            PublicationsFileContainsSignaturePublicationRule rule = new PublicationsFileContainsSignaturePublicationRule();

            // Check legacy signature
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Legacy_Ok_With_Publication_Record), FileMode.Open))
            {
                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
                testPublicationsFile.PublicationRecords.Add(
                    new PublicationRecordInPublicationFile(new RawTag(0x703, false, false,
                        Base16.Decode("3029020455CE810004210115BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268013"))));

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
        public void TestSignatureWithPublicationsFilePublication()
        {
            PublicationsFileContainsSignaturePublicationRule rule = new PublicationsFileContainsSignaturePublicationRule();

            // Check signature
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok_With_Publication_Record), FileMode.Open))
            {
                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
                testPublicationsFile.PublicationRecords.Add(
                    new PublicationRecordInPublicationFile(new RawTag(0x703, false, false,
                        Base16.Decode("3029020455CE810004210115BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268013"))));

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
        public void TestVerify()
        {
            PublicationsFileContainsSignaturePublicationRule rule = new PublicationsFileContainsSignaturePublicationRule();

            // Check invalid signature with publication record missing from publications file
            using (FileStream stream = 
                new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Invalid_With_Invalid_Publication_Record), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = new TestPublicationsFile()
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Na, verificationResult.ResultCode);
            }
        }
    }
}