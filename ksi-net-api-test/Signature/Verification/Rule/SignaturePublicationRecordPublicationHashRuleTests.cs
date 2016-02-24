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
using NUnit.Framework;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture]
    public class SignaturePublicationRecordPublicationHashRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            SignaturePublicationRecordPublicationHashRule rule = new SignaturePublicationRecordPublicationHashRule();

            // Argument null exception when no context
            Assert.Throws<KsiException>(delegate
            {
                rule.Verify(null);
            });
        }

        [Test]
        public void TestContextMissingSignature()
        {
            SignaturePublicationRecordPublicationHashRule rule = new SignaturePublicationRecordPublicationHashRule();

            // Verification exception on missing KSI signature 
            Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();

                rule.Verify(context);
            });
        }

        [Test]
        public void TestRfc3161SignaturePublicationRecordAndMissingCalendarHashChain()
        {
            SignaturePublicationRecordPublicationHashRule rule = new SignaturePublicationRecordPublicationHashRule();

            // Check legacy signature for missing calendar hash chain and existing publication record
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Legacy_Ok_With_Publication_Record, FileMode.Open))
            {
                Assert.Throws<KsiVerificationException>(delegate
                {
                    IKsiSignature signature = new KsiSignatureFactory().Create(stream);
                    TestVerificationContext context = new TestVerificationContext()
                    {
                        Signature = new TestKsiSignature()
                        {
                            PublicationRecord = signature.PublicationRecord
                        }
                    };

                    rule.Verify(context);
                });
            }
        }

        [Test]
        public void TestSignatureMissingPublicationRecord()
        {
            SignaturePublicationRecordPublicationHashRule rule = new SignaturePublicationRecordPublicationHashRule();

            // Check signature without publications record
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestRfc3161SignaturePublicationRecordHash()
        {
            SignaturePublicationRecordPublicationHashRule rule = new SignaturePublicationRecordPublicationHashRule();

            // Check legacy signature with publications record
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Legacy_Ok_With_Publication_Record, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestSignaturePublicationRecordHash()
        {
            SignaturePublicationRecordPublicationHashRule rule = new SignaturePublicationRecordPublicationHashRule();

            // Check signature with publications record
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_With_Publication_Record, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestSignatureInvalidPublicationRecordHash()
        {
            SignaturePublicationRecordPublicationHashRule rule = new SignaturePublicationRecordPublicationHashRule();

            // Check invalid signature with invalid publication record
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Invalid_With_Invalid_Publication_Record, FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
            }
        }
    }
}