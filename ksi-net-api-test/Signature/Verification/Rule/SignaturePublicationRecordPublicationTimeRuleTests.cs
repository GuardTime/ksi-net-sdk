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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class SignaturePublicationRecordPublicationTimeRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            SignaturePublicationRecordPublicationTimeRule rule = new SignaturePublicationRecordPublicationTimeRule();

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
            SignaturePublicationRecordPublicationTimeRule rule = new SignaturePublicationRecordPublicationTimeRule();

            // Verification exception on missing KSI signature 
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();

                rule.Verify(context);
            });
            Assert.That(ex.Message, Does.StartWith("Invalid KSI signature in context: null"));
        }

        [Test]
        public void TestSignaturePublicationRecordAndMissingCalendarHashChain()
        {
            SignaturePublicationRecordPublicationTimeRule rule = new SignaturePublicationRecordPublicationTimeRule();

            // Check signature with publication record and calendar hash chain is missing
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new TestKsiSignature()
                    {
                        PublicationRecord = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record).PublicationRecord
                    }
                };

                rule.Verify(context);
            });
            Assert.That(ex.Message, Does.StartWith("Calendar hash chain is missing from KSI signature"));
        }

        [Test]
        public void TestSignatureMissingPublicationRecord()
        {
            SignaturePublicationRecordPublicationTimeRule rule = new SignaturePublicationRecordPublicationTimeRule();

            // Check signature without publication record
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature()
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        [Test]
        public void TestRfc3161SignaturePublicationRecordTime()
        {
            SignaturePublicationRecordPublicationTimeRule rule = new SignaturePublicationRecordPublicationTimeRule();

            // Check legacy signature with publication record
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok_With_Publication_Record)
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        [Test]
        public void TestSignaturePublicationRecordTime()
        {
            SignaturePublicationRecordPublicationTimeRule rule = new SignaturePublicationRecordPublicationTimeRule();

            // Check signature with publication record
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record)
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        [Test]
        public void TestSignatureInvalidPublicationRecordTime()
        {
            SignaturePublicationRecordPublicationTimeRule rule = new SignaturePublicationRecordPublicationTimeRule();

            // Check invalid signature with invalid publication record
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_With_Invalid_Publication_Record_Time)
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
            Assert.AreEqual(VerificationError.Int07, verificationResult.VerificationError);
        }
    }
}