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
    public class PublicationsFileSignaturePublicationMatchRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            PublicationsFileSignaturePublicationMatchRule rule = new PublicationsFileSignaturePublicationMatchRule();

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
            PublicationsFileSignaturePublicationMatchRule rule = new PublicationsFileSignaturePublicationMatchRule();

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
            PublicationsFileSignaturePublicationMatchRule rule = new PublicationsFileSignaturePublicationMatchRule();

            // No publications file defined
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok), FileMode.Open))
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
            PublicationsFileSignaturePublicationMatchRule rule = new PublicationsFileSignaturePublicationMatchRule();

            // Check signature with not publications record
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok), FileMode.Open))
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
            PublicationsFileSignaturePublicationMatchRule rule = new PublicationsFileSignaturePublicationMatchRule();

            // Check legacy signature
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Legacy_Ok_With_Publication_Record), FileMode.Open))
            {
                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
                testPublicationsFile.NearestPublications.Add(1439596800,
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
            PublicationsFileSignaturePublicationMatchRule rule = new PublicationsFileSignaturePublicationMatchRule();

            // Check signature publication record against publications file
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok_With_Publication_Record), FileMode.Open))
            {
                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
                testPublicationsFile.NearestPublications.Add(1439596800,
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
        public void TestSignatureWithPublicationsFileInvalidPublication()
        {
            PublicationsFileSignaturePublicationMatchRule rule = new PublicationsFileSignaturePublicationMatchRule();

            // Check signature publication record against publications file. Publication hash mismatch.
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok_With_Publication_Record), FileMode.Open))
            {
                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
                testPublicationsFile.NearestPublications.Add(1439596800,
                    new PublicationRecordInPublicationFile(new RawTag(0x703, false, false,
                        Base16.Decode("3029020455CE810004210115BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268014"))));

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = testPublicationsFile
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Pub05.Code, verificationResult.VerificationError.Code);
            }
        }

        [Test]
        public void TestSignatureWithPubRecordMissingInPubFile()
        {
            PublicationsFileSignaturePublicationMatchRule rule = new PublicationsFileSignaturePublicationMatchRule();

            // Check invalid signature with publication record missing in publications file
            using (FileStream stream =
                new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok_With_Publication_Record), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                    PublicationsFile = new TestPublicationsFile()
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Na, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestSignatureWithPubRecordMissingInPubFileButCanExtend()
        {
            PublicationsFileSignaturePublicationMatchRule rule = new PublicationsFileSignaturePublicationMatchRule();

            // Check signature with publication record missing in publications file, but can be extended to a publication in publications file
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok_With_Publication_Record), FileMode.Open))
            {
                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
                testPublicationsFile.NearestPublications.Add(1439596800,
                    new PublicationRecordInPublicationFile(new RawTag(0x703, false, false,
                        Base16.Decode("3029020455ce349a04210115BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268013"))));

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = testPublicationsFile
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Na, verificationResult.ResultCode);
            }
        }
    }
}