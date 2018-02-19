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
    public class InputHashAlgorithmDeprecatedRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new InputHashAlgorithmDeprecatedRule();

        [Test]
        public void TestRfc3161SignatureWithOkAlgorithm()
        {
            // Check legacy signature input hash that use hash algorithm without deprecated date
            CreateSignatureAndVerify(Resources.KsiSignature_Legacy_Ok, VerificationResultCode.Ok);
        }

        [Test]
        public void TestRfc3161SignatureWithOkAlgorithmBeforeDeprecatedDate()
        {
            // Check legacy signature input hash that use hash algorithm with deprecated date and aggregation time is before deprecated date
            CreateSignatureAndVerify(Resources.KsiSignature_Rfc3161Record_Sha1InputHashAlgorithm_2016, VerificationResultCode.Ok);
        }

        [Test]
        public void TestRfc3161SignatureWithInvalidAlgorithmAfterDeprecatedDate()
        {
            // Check legacy signature input hash that use hash algorithm with deprecated date and aggregation time is after deprecated date
            CreateSignatureAndVerify(Resources.KsiSignature_Rfc3161Record_Sha1InputHashAlgorithm_2017, VerificationResultCode.Fail, VerificationError.Int13);
        }

        [Test]
        public void TestOkAlgorithm()
        {
            // Check signature input hash that use hash algorithm without deprecated date
            CreateSignatureAndVerify(Resources.KsiSignature_Ok, VerificationResultCode.Ok);
        }

        [Test]
        public void TestOkAlgorithmBeforeDeprecatedDate()
        {
            // Check signature input hash that use hash algorithm with deprecated date and aggregation time is before deprecated date
            CreateSignatureAndVerify(Resources.KsiSignature_Sha1InputAlgorithm_2016, VerificationResultCode.Ok);
        }

        [Test]
        public void TestInvalidAlgorithmAfterDeprecatedDate()
        {
            // Check signature input hash that use hash algorithm with deprecated date and aggregation time is after deprecated date
            CreateSignatureAndVerify(Resources.KsiSignature_Sha1InputAlgorithm_2017, VerificationResultCode.Fail, VerificationError.Int13);
        }
    }
}