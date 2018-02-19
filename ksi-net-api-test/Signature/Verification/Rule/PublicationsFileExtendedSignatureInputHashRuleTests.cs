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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Test.Publication;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class PublicationsFileExtendedSignatureInputHashRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new PublicationsFileExtendedSignatureInputHashRule();

        [Test]
        public void TestContextMissingPublicationsFile()
        {
            base.TestContextMissingPublicationsFile();
        }

        [Test]
        public void TestSignatureWithInvalidContextExtendFunctions()
        {
            // Check invalid extended calendar chain from context function: null
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(),
                PublicationsFile = GetPublicationsFile(1455478441)
            };

            TestSignatureWithInvalidContextExtendFunctions(context);
        }

        [Test]
        public void TestSignatureWithMissingNewerPublication()
        {
            // Check no publication found after current signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok),
                PublicationsFile = new TestPublicationsFile(),
            };

            DoesThrow<KsiVerificationException>(delegate
            {
                Rule.Verify(context);
            }, "No publication record found after given time in publications file");
        }

        [Test]
        public void TestRfc3161SignatureExtendInputHash()
        {
            // Check legacy signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok_With_Publication_Record),
                PublicationsFile = GetPublicationsFile(1401915603),
                ExtendedCalendarHashChain = GetExtendedCalendarHashChain("01145C6CDA9F901A65C0B3C09896675928E1A85977280BF65C0A638C8A47BB358A")
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureExtendInputHash()
        {
            // Check signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record),
                PublicationsFile = GetPublicationsFile(1439577241),
                ExtendedCalendarHashChain = GetExtendedCalendarHashChain("012E86118343FBFF0422986896C42363DB331EBDE356303C1DFC3F33B2FDC39B08")
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureWithInvalidPublicationRecord()
        {
            // Signature last aggregation hash chain root hash and extended calendar hash chain input hash mismatch.
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record),
                PublicationsFile = GetPublicationsFile(1439577241),
                ExtendedCalendarHashChain = GetExtendedCalendarHashChain("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Pub03);
        }

        private static TestPublicationsFile GetPublicationsFile(ulong aggregationTime)
        {
            return GetPublicationsFile(aggregationTime, 1408060800, "01F41157B228426C657EF81740CABAE530572C313DC4DA916306E67BD9B7742865");
        }

        private CalendarHashChain GetExtendedCalendarHashChain(string encodedInputHash)
        {
            TlvTagBuilder builder = new TlvTagBuilder(Constants.CalendarHashChain.TagType, false, false);
            builder.AddChildTag(new IntegerTag(Constants.CalendarHashChain.PublicationTimeTagType, false, false, 1));
            builder.AddChildTag(new ImprintTag(Constants.CalendarHashChain.InputHashTagType, false, false, new DataHash(Base16.Decode(encodedInputHash))));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Left, false, false, Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")));
            return new CalendarHashChain(builder.BuildTag());
        }
    }
}