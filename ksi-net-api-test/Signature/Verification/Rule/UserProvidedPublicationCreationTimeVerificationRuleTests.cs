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
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class UserProvidedPublicationCreationTimeVerificationRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new UserProvidedPublicationCreationTimeVerificationRule();

        [Test]
        public void TestContextMissingUserPublication()
        {
            base.TestContextMissingUserPublication();
        }

        [Test]
        public void TestSignatureWithAggregationChainOnly()
        {
            // Check signature with aggregation chain only.
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_AggregationHashChain_Only),
                UserPublication = GetUserPublication(1439596800)
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestRfc3161SignatureWithUserPublicationTime()
        {
            // Check extended legacy signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok),
                UserPublication = GetUserPublication(1439596800)
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureWithUserPublicationTime()
        {
            // Check extended signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok),
                UserPublication = GetUserPublication(1455478442)
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureWithInvalidUserPublicationTime()
        {
            // Check invalid signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok),
                UserPublication = GetUserPublication(1455478441)
            };

            Verify(context, VerificationResultCode.Na);
        }

        private static PublicationData GetUserPublication(ulong publicationTime)
        {
            return new PublicationData(publicationTime, new DataHash(Base16.Decode("0115BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268013")));
        }
    }
}