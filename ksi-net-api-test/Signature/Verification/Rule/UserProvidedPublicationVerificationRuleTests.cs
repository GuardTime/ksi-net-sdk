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
    public class UserProvidedPublicationVerificationRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new UserProvidedPublicationVerificationRule();

        [Test]
        public void TestSignatureMissingPublicationRecord()
        {
            base.TestSignatureMissingPublicationRecord(new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok),
                UserPublication = new PublicationData(1439596801, new DataHash(Base16.Decode("0115BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268013")))
            });
        }

        [Test]
        public void TestContextMissingUserPublication()
        {
            TestContextMissingUserPublication(TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record));
        }

        [Test]
        public void TestWithPublicationTimeMismatch()
        {
            // Check invalid signature. Publication hash match but time mismatch.
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record),
                UserPublication = new PublicationData(1439596801, new DataHash(Base16.Decode("0115BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268013")))
            };

            Verify(context, VerificationResultCode.Na);
        }

        [Test]
        public void TestWithPublicationHashMismatch()
        {
            // Check invalid signature. Publication time match but hash mismatch.
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record),
                UserPublication = new PublicationData(1439596800, new DataHash(Base16.Decode("0125BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268014")))
            };
            Verify(context, VerificationResultCode.Fail, VerificationError.Pub04);
        }

        [Test]
        public void TestRfc3161Signature()
        {
            // Check legacy signature with publication record
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok_With_Publication_Record),
                UserPublication = new PublicationData(1439596800, new DataHash(Base16.Decode("0115BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268013")))
            };
            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignature()
        {
            // Check signature with publication record
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record),
                UserPublication = new PublicationData(1439596800, new DataHash(Base16.Decode("0115BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268013")))
            };

            Verify(context, VerificationResultCode.Ok);
        }
    }
}