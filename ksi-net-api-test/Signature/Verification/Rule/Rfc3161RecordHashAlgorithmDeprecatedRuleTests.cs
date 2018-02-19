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
    public class Rfc3161RecordHashAlgorithmDeprecatedRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new Rfc3161RecordHashAlgorithmDeprecatedRule();

        [Test]
        public void TestNonRfc3161Signature()
        {
            // test using non-legacy signature
            CreateSignatureAndVerify(Resources.KsiSignature_Sha1AggregationChainAlgorithm_2017, VerificationResultCode.Ok);
        }

        [Test]
        public void TestOkAlgorithms()
        {
            // test using hash algorithms without deprecated date
            CreateSignatureAndVerify(Resources.KsiSignature_Legacy_Ok, VerificationResultCode.Ok);
        }

        [Test]
        public void TestTstInfoAlgorithmBeforeDeprecatedDate()
        {
            // test with TstInfo that use hash algorithm with deprecated date and aggregation time is before deprecated date
            CreateSignatureAndVerify(Resources.KsiSignature_Rfc3161Record_Sha1TstInfoAlgorithm_2016, VerificationResultCode.Ok);
        }

        [Test]
        public void TestTstInfoAlgorithmAfterDeprecatedDate()
        {
            // test with TstInfo that use hash algorithm with deprecated date and aggregation time is after deprecated date
            CreateSignatureAndVerify(Resources.KsiSignature_Rfc3161Record_Sha1TstInfoAlgorithm_2017, VerificationResultCode.Fail, VerificationError.Int14);
        }

        [Test]
        public void TestSignedAttrAlgorithmBeforeDeprecatedDate()
        {
            // test with SignedAttributes that use hash algorithm with deprecated date and aggregation time is before deprecated date
            CreateSignatureAndVerify(Resources.KsiSignature_Rfc3161Record_Sha1SignedAttrAlgorithm_2016, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignedAttrAlgorithmAfterDeprecatedDate()
        {
            // test with SignedAttributes that use hash algorithm with deprecated date and aggregation time is after deprecated date
            CreateSignatureAndVerify(Resources.KsiSignature_Rfc3161Record_Sha1SignedAttrAlgorithm_2017, VerificationResultCode.Fail, VerificationError.Int14);
        }
    }
}