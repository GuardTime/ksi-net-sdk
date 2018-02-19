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

using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class UserProvidedPublicationTimeMatchesExtendedResponseRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new UserProvidedPublicationTimeMatchesExtendedResponseRule();

        [Test]
        public override void TestContextMissingSignature()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                ExtendedCalendarHashChain = TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended).CalendarHashChain,
                UserPublication = GetUserPublication(1455494400)
            };

            TestContextMissingSignature(context);
        }

        [Test]
        public void TestContextMissingUserPublication()
        {
            base.TestContextMissingUserPublication();
        }

        [Test]
        public void TestSignatureWithInvalidContextExtendFunctions()
        {
            // Check invalid extended calendar chain from context extension function
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok),
                UserPublication = GetUserPublication(1455494400)
            };

            TestSignatureWithInvalidContextExtendFunctions(context);
        }

        [Test]
        public void TestSignatureAggregationTimeWithInvalidRegistrationTime()
        {
            // Aggregation time and calculated registration time mismatch
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = new TestKsiSignature() { AggregationTime = 1455478442 },
                ExtendedCalendarHashChain = TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended).CalendarHashChain,
                UserPublication = GetUserPublication(1455494400)
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Pub02);
        }

        [Test]
        public void TestPublicationRecordPublicationTimeWithInvalidPublicationTime()
        {
            // Publication times from publication record and extended calendar hash chain do not match
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok),
                ExtendedCalendarHashChain = TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended).CalendarHashChain,
                UserPublication = GetUserPublication(1455494401)
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Pub02);
        }

        [Test]
        public void TestSignature()
        {
            // Check signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok),
                ExtendedCalendarHashChain = TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended).CalendarHashChain,
                UserPublication = GetUserPublication(1455494400)
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestRfc3161Signature()
        {
            // Check legacy signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok),
                ExtendedCalendarHashChain = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok_With_Publication_Record).CalendarHashChain,
                UserPublication = GetUserPublication(1439596800)
            };

            Verify(context, VerificationResultCode.Ok);
        }

        private static PublicationData GetUserPublication(ulong publicationTime)
        {
            return new PublicationData(publicationTime, new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")));
        }
    }
}