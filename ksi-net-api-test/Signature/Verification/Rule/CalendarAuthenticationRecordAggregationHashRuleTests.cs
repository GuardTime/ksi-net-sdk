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
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class CalendarAuthenticationRecordAggregationHashRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            CalendarAuthenticationRecordAggregationHashRule rule = new CalendarAuthenticationRecordAggregationHashRule();

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
            CalendarAuthenticationRecordAggregationHashRule rule = new CalendarAuthenticationRecordAggregationHashRule();

            // Verification exception on missing KSI signature 
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();

                rule.Verify(context);
            });
            Assert.That(ex.Message, Does.StartWith("Invalid KSI signature in context: null"));
        }

        [Test]
        public void TestRfc3161SignatureMissingCalendarHashChain()
        {
            CalendarAuthenticationRecordAggregationHashRule rule = new CalendarAuthenticationRecordAggregationHashRule();

            // Check legacy signature for missing calendar hash chain and existing calendar authentication record
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                IKsiSignature signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok);
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new TestKsiSignature()
                    {
                        CalendarAuthenticationRecord = signature.CalendarAuthenticationRecord
                    }
                };

                rule.Verify(context);
            });
            Assert.That(ex.Message, Does.StartWith("Calendar hash chain is missing from KSI signature"));
        }

        [Test]
        public void TestRfc3161SignatureCalendarAuthenticationRecord()
        {
            CalendarAuthenticationRecordAggregationHashRule rule = new CalendarAuthenticationRecordAggregationHashRule();

            // Check legacy signature for calendar authentication record hash
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok)
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        [Test]
        public void TestSignatureCalendarAuthenticationRecord()
        {
            CalendarAuthenticationRecordAggregationHashRule rule = new CalendarAuthenticationRecordAggregationHashRule();

            // Check signature for calendar authentication record hash
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature()
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        [Test]
        public void TestSignatureMissingCalendarAuthenticationRecord()
        {
            CalendarAuthenticationRecordAggregationHashRule rule = new CalendarAuthenticationRecordAggregationHashRule();

            // Check signature with no calendar authentication record
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_AggregationHashChain_Only)
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        [Test]
        public void TestSignatureWithInvalidPublicationHashInCalendarAuthenticationRecord()
        {
            CalendarAuthenticationRecordAggregationHashRule rule = new CalendarAuthenticationRecordAggregationHashRule();

            // Check invalid signature with invalid publication hash in calendar authentication record

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Calendar_Authentication_Record_Invalid_Publication_Hash)
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
            Assert.AreEqual(VerificationError.Int08, verificationResult.VerificationError);
        }
    }
}