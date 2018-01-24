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

using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class ExtendedSignatureCalendarChainAggregationTimeRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new ExtendedSignatureCalendarChainAggregationTimeRule();

        [Test]
        public void TestSignatureMissingCalendarHashChain()
        {
            // Missing calendar hash chain does not make the verification to fail.
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_AggregationHashChain_Only),
                LatestCalendarHashChain = GetExtendedCalendarHashChain(1404215325)
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureWithInvalidContextExtendFunctions()
        {
            // Check invalid extended calendar chain returned by context extension function
            base.TestSignatureWithInvalidContextExtendFunctions();
        }

        [Test]
        public void TestRfc3161SignatureCalendarHashChainAggregationTime()
        {
            // Check legacy signature calendar hash chain aggregation time
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok),
                ExtendedCalendarHashChain = GetExtendedCalendarHashChain(1401915603)
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureCalendarHashChainAggregationTime()
        {
            // Check signature calendar hash chain aggregation time
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(),
                ExtendedCalendarHashChain = GetExtendedCalendarHashChain(1455478441)
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureExtendedCalendarHashChainAggregationTimeDiffers()
        {
            // Aggregation time does not match
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record),
                ExtendedCalendarHashChain = GetExtendedCalendarHashChain(123456789)
            };
            Verify(context, VerificationResultCode.Fail, VerificationError.Cal03);
        }

        private CalendarHashChain GetExtendedCalendarHashChain(ulong aggregationTime)
        {
            TlvTagBuilder builder = new TlvTagBuilder(Constants.CalendarHashChain.TagType, false, false);
            builder.AddChildTag(new IntegerTag(Constants.CalendarHashChain.PublicationTimeTagType, false, false, aggregationTime));
            builder.AddChildTag(new IntegerTag(Constants.CalendarHashChain.AggregationTimeTagType, false, false, aggregationTime));
            builder.AddChildTag(new ImprintTag(Constants.CalendarHashChain.InputHashTagType, false, false,
                new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2"))));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Left, false, false, Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")));
            return new CalendarHashChain(builder.BuildTag());
        }
    }
}