/*
 * Copyright 2013-2018 Guardtime, Inc.
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

using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class ExtendedSignatureCalendarChainRootHashRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new ExtendedSignatureCalendarChainRootHashRule();

        [Test]
        public void TestSignatureMissingCalendarHashChain()
        {
            TestSignatureMissingCalendarHashChain(TestUtil.GetSignature(Resources.KsiSignature_Ok_AggregationHashChain_Only));
        }

        [Test]
        public void TestSignatureWithInvalidContextExtendFunctions()
        {
            base.TestSignatureWithInvalidContextExtendFunctions();
        }

        [Test]
        public void TestRfc3161SignatureExtendedCalendarHashChainRootHash()
        {
            // Check legacy signature
            KsiSignature signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok_With_Publication_Record);
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = signature,
                ExtendedCalendarHashChain = signature.CalendarHashChain
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureExtendedCalendarHashChainRootHash()
        {
            // Check signature
            KsiSignature signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record);
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = signature,
                ExtendedCalendarHashChain = signature.CalendarHashChain
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureExtendedCalendarHashChainInvalidRootHash()
        {
            // Check invalid signature output hash
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record),
                ExtendedCalendarHashChain = TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended).CalendarHashChain
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Cal01);
        }
    }
}