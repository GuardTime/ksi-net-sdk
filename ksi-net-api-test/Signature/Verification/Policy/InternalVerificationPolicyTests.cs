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
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Test.Signature.Verification.Rule;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Policy
{
    [TestFixture]
    public class InternalVerificationPolicyTests : RuleTestsBase
    {
        public override VerificationRule Rule => new InternalVerificationPolicy();

        [Test]
        public void InternalVerificationPolicyOkTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(),
                DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"))
            };
            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void InternalVerificationPolicyInvalidDocumentHashTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(),
                DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772E"))
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Gen01);
        }

        [Test]
        public void InternalVerificationPolicyInvalidDocumentHashAlgorithmTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(),
                DocumentHash = new DataHash(Base16.Decode("0411A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772DE1A7F49828C340C328C340C328C340C3"))
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Gen04);
        }

        [Test]
        public void InternalVerificationPolicyInvalidDocumentHashLevelTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(),
                DocumentHashLevel = 1,
                DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"))
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Gen03);
        }

        [Test]
        public void InternalVerificationPolicyInvalidAggregationChainInputHashTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Invalid_Input),
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Int01);
        }

        [Test]
        public void InternalVerificationPolicyInvalidRfc3161RecordAggregationTimeTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Rfc3161_Aggregation_Time_Mismatch),
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Int02);
        }

        [Test]
        public void InternalVerificationPolicyInvalidRfc3161RecordChainIndexTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Rfc3161_Chain_Index_Mismatch),
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Int12);
        }

        [Test]
        public void InternalVerificationPolicyInvalidAggregationHashChainIndexSuccessorTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Aggregation_Chain_Index_Mismatch_Prev),
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Int12);
        }

        [Test]
        public void InternalVerificationPolicyInvalidAggregationHashChainMetadataTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.AggregationHashChainMetadataPaddingNotFirstFail)
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Int11);
        }

        [Test]
        public void InternalVerificationPolicyInvalidAggregationHashChainConsistencyTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Aggregation_Chain_Input_Hash)
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Int01);
        }

        [Test]
        public void InternalVerificationPolicyInvalidAggregationHashChainTimeConsistencyTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Aggregation_Chain_Aggregation_Time_Mismatch)
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Int02);
        }

        [Test]
        public void InternalVerificationPolicyInvalidAggregationHashChainIndexTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Aggregation_Chain_Index_Mismatch)
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Int10);
        }

        [Test]
        public void InternalVerificationPolicyInvalidCalendarHashChainInputHashVerificationTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Calendar_Chain_Input_Hash)
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Int03);
        }

        [Test]
        public void InternalVerificationPolicyInvalidCalendarHashChainAggregationTimeTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Calendar_Chain_Aggregation_Time)
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Int04);
        }

        [Test]
        public void InternalVerificationPolicyInvalidCalendarHashChainRegistrationTimeTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Calendar_Chain_Registration_Time)
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Int05);
        }

        [Test]
        public void InternalVerificationPolicyInvalidCalendarAuthenticationRecordAggregationHashTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Calendar_Authentication_Record_Invalid_Publication_Hash)
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Int08);
        }

        [Test]
        public void InternalVerificationPolicyInvalidCalendarAuthenticationRecordAggregationTimeTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Calendar_Authentication_Record_Invalid_Publication_Time)
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Int06);
        }

        [Test]
        public void InternalVerificationPolicyInvalidSignaturePublicationRecordPublicationHashTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_With_Invalid_Publication_Record_Hash)
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Int09);
        }

        [Test]
        public void InternalVerificationPolicyInvalidSignaturePublicationRecordPublicationTimeTest()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_With_Invalid_Publication_Record_Time)
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Int07);
        }
    }
}