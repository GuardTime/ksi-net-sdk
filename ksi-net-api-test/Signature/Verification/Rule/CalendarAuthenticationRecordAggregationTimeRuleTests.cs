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
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class CalendarAuthenticationRecordAggregationTimeRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            CalendarAuthenticationRecordAggregationTimeRule rule = new CalendarAuthenticationRecordAggregationTimeRule();

            // Argument null exception when no context
            Assert.Throws<KsiException>(delegate
            {
                rule.Verify(null);
            });
        }

        [Test]
        public void TestContextMissingSignature()
        {
            CalendarAuthenticationRecordAggregationTimeRule rule = new CalendarAuthenticationRecordAggregationTimeRule();

            // Verification exception on missing KSI signature 
            Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();

                rule.Verify(context);
            });
        }

        [Test]
        public void TestRfc3161SignatureMissingCalendarHashChain()
        {
            CalendarAuthenticationRecordAggregationTimeRule rule = new CalendarAuthenticationRecordAggregationTimeRule();

            // Check legacy signature for missing calendar hash chain and existing calendar authentication record
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Legacy_Ok), FileMode.Open))
            {
                Assert.Throws<KsiVerificationException>(delegate
                {
                    IKsiSignature signature = new KsiSignatureFactory().Create(stream, false);
                    TestVerificationContext context = new TestVerificationContext()
                    {
                        Signature = new TestKsiSignature()
                        {
                            CalendarAuthenticationRecord = signature.CalendarAuthenticationRecord
                        }
                    };

                    rule.Verify(context);
                });
            }
        }

        [Test]
        public void TestRfc3161SignatureAuthenticationRecordAggregationTime()
        {
            CalendarAuthenticationRecordAggregationTimeRule rule = new CalendarAuthenticationRecordAggregationTimeRule();

            // Check legacy signature for authentication record aggregation time
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Legacy_Ok), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream, false)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestSignatureAuthenticationRecordAggregationTime()
        {
            CalendarAuthenticationRecordAggregationTimeRule rule = new CalendarAuthenticationRecordAggregationTimeRule();

            // Check signature for calendar authentication record aggregation time
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream, false)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestSignatureMissingAuthenticationRecord()
        {
            CalendarAuthenticationRecordAggregationTimeRule rule = new CalendarAuthenticationRecordAggregationTimeRule();

            // Check signature with no calendar authentication record
            using (FileStream stream =
                new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok_Missing_Publication_Record_And_Calendar_Authentication_Record),
                    FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream, false)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestSignatureWithInvalidPublicationTime()
        {
            CalendarAuthenticationRecordAggregationTimeRule rule = new CalendarAuthenticationRecordAggregationTimeRule();

            // Check invalid signature with invalid publication time
            using (FileStream stream =
                new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Invalid_Calendar_Authentication_Record_Invalid_Publication_Time),
                    FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream, false)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Int06, verificationResult.VerificationError);
            }
        }
    }
}