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

using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class AggregationHashChainIndexSuccessorRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new AggregationHashChainIndexSuccessorRule();

        [Test]
        public void TestSignatureMissingAggregationHashChain()
        {
            TestSignatureMissingAggregationHashChain(null, true);
        }

        [Test]
        public void TestRfc3161SignatureAggregationHashChainIndexSuccessor()
        {
            // Check legacy signature for aggregation hash chain index match against previous chain index
            CreateSignatureAndVerify(Resources.KsiSignature_Legacy_Ok, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureAggregationHashChainIndexSuccessor()
        {
            // Check signature for aggregation hash chain index match against previous chain index
            CreateSignatureAndVerify(Resources.KsiSignature_Ok, VerificationResultCode.Ok);
        }

        [Test]
        public void TestInvalidSignatureAggregationHashChainIndexSuccessor()
        {
            // Check invalid signature for aggregation hash chain index mismatch against previous chain index (Chain index: 11, 879, 475, 3951, 3; Parent chain index: 11, 879, 475, 255)
            CreateSignatureAndVerify(Resources.KsiSignature_Invalid_Aggregation_Chain_Index_Mismatch_Prev, VerificationResultCode.Fail, VerificationError.Int12);
        }

        [Test]
        public void TestInvalidSignatureAggregationHashChainIndexSuccessor2()
        {
            // Check invalid signature for aggregation hash chain index mismatch against previous chain index (Length mismatch. Chain index: 11, 879, 475, 3951; Parent chain index: 11, 879, 475, 3951)
            CreateSignatureAndVerify(Resources.KsiSignature_Invalid_Aggregation_Chain_Index_Mismatch_Prev2, VerificationResultCode.Fail, VerificationError.Int12);
        }

        [Test]
        public void TestInvalidSignatureHighestAggregationHashChainIndexLength()
        {
            // The highest aggregation hash chain index length is not 1
            CreateSignatureAndVerify(Resources.KsiSignature_Invalid_Highest_Aggregation_Chain_Index_Length, VerificationResultCode.Fail, VerificationError.Int12);
        }
    }
}