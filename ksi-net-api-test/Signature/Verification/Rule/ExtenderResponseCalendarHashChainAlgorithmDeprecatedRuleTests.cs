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
using Guardtime.KSI.Test.Publication;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class ExtenderResponseCalendarHashChainAlgorithmDeprecatedTests : RuleTestsBase
    {
        public override VerificationRule Rule => new ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule();

        [Test]
        public void TestOkAlgorithm()
        {
            // Check extender response calendar hash chains that use hash algorithms without deprecated date
            Verify(Resources.KsiSignature_Ok, VerificationResultCode.Ok);
        }

        [Test]
        public void TestOkAlgorithmBeforeDeprecatedDate()
        {
            // Check extender response calendar hash chain that use hash algorithms with deprecated date and publication time is before deprecated date
            Verify(Resources.KsiSignature_Sha1CalendarLeftLinkAlgorithm_2016, VerificationResultCode.Ok);
        }

        [Test]
        public void TestInvalidAlgorithmAfterDeprecatedDate()
        {
            // Check extender response calendar hash chain that use hash algorithms with deprecated date and publication time is after deprecated date
            Verify(Resources.KsiSignature_Sha1CalendarLeftLinkAlgorithm_2017, VerificationResultCode.Na);
        }

        [Test]
        public void TestPublicationsFileMissingNewerPublicationRecord()
        {
            // Check no publication found after current signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(),
                PublicationsFile = new TestPublicationsFile(),
            };

            Verify(context, VerificationResultCode.Na);
        }

        private void Verify(string signaturePath, VerificationResultCode resultCode)
        {
            IKsiSignature signature = TestUtil.GetSignature(signaturePath);

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = signature,
                PublicationsFile = GetPublicationsFile(signature.AggregationTime, 1439577242, "0115BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268013"),
                ExtendedCalendarHashChain = signature.CalendarHashChain
            };

            Verify(context, resultCode);
        }
    }
}