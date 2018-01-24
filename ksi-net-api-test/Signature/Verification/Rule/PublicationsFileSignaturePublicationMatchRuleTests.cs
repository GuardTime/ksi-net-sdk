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

using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Test.Publication;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class PublicationsFileSignaturePublicationMatchRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new PublicationsFileSignaturePublicationMatchRule();

        [Test]
        public override void TestContextMissingSignature()
        {
            TestContextMissingSignature(new TestVerificationContext() { PublicationsFile = new TestPublicationsFile() });
        }

        [Test]
        public void TestContextMissingPublicationsFile()
        {
            base.TestContextMissingPublicationsFile();
        }

        [Test]
        public void TestSignatureMissingPublicationRecord()
        {
            TestSignatureMissingPublicationRecord(new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(),
                PublicationsFile = new TestPublicationsFile()
            });
        }

        [Test]
        public void TestSignatureWithPubRecordMissingInPubFile()
        {
            // Check invalid signature with publication record missing in publications file
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record),
                PublicationsFile = new TestPublicationsFile()
            };

            Verify(context, VerificationResultCode.Na);
        }

        [Test]
        public void TestRfc3161SignatureWithPublicationsFile()
        {
            // Check legacy signature publication record against publications file
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok_With_Publication_Record),
                PublicationsFile = GetPublicationsFile(1439596800, 1439596800, "0115BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268013")
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureWithPublicationsFile()
        {
            // Check signature publication record against publications file
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record),
                PublicationsFile = GetPublicationsFile(1439596800, 1439596800, "0115BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268013")
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureWithPublicationHashMismatch()
        {
            // Check signature publication record against publications file. Publication hash mismatch.
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record),
                PublicationsFile = GetPublicationsFile(1439596800, 1439596800, "0125BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268014")
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Pub05);
        }

        [Test]
        public void TestSignatureWithPublicationTimeMismatch()
        {
            // Check signature publication record against publications file. Publication time mismatch.
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record),
                PublicationsFile = GetPublicationsFile(1439596800, 1439597000, "0115BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268013")
            };
            Verify(context, VerificationResultCode.Na);
        }
    }
}