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

using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class CalendarAuthenticationRecordAggregationTimeRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new CalendarAuthenticationRecordAggregationTimeRule();

        [Test]
        public void TestSignatureMissingCalendarHashChain()
        {
            // Check signature for missing calendar hash chain and existing calendar authentication record
            TestSignatureMissingCalendarHashChain(new TestKsiSignature()
            {
                CalendarAuthenticationRecord = TestUtil.GetSignature(Resources.KsiSignature_Ok).CalendarAuthenticationRecord
            });
        }

        [Test]
        public void TestRfc3161SignatureAuthenticationRecordAggregationTime()
        {
            // Check legacy signature for authentication record aggregation time
            CreateSignatureAndVerify(Resources.KsiSignature_Legacy_Ok, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureAuthenticationRecordAggregationTime()
        {
            // Check signature for calendar authentication record aggregation time
            CreateSignatureAndVerify(Resources.KsiSignature_Ok, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureMissingAuthenticationRecord()
        {
            // Check signature with no calendar authentication record
            CreateSignatureAndVerify(Resources.KsiSignature_Ok_AggregationHashChain_Only, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureWithInvalidPublicationTime()
        {
            // Check invalid signature with invalid publication time
            CreateSignatureAndVerify(Resources.KsiSignature_Invalid_Calendar_Authentication_Record_Invalid_Publication_Time, VerificationResultCode.Fail, VerificationError.Int06);
        }
    }
}