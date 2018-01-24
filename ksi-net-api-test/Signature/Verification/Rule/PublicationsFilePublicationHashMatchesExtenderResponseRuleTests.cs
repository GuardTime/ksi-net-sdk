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
    public class PublicationsFilePublicationHashMatchesExtenderResponseRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new PublicationsFilePublicationHashMatchesExtenderResponseRule();

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
        public void TestSignatureWithInvalidContextExtendFunctions()
        {
            //// Check invalid extended calendar chain from context function: null
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Missing_Calendar_Authentication_Record),
                PublicationsFile = GetPublicationsFile(1455478441, "01B746442100F4C41F556B8D186FEF33A062234808BECF236A9EB8D23485CD4C3E")
            };

            TestSignatureWithInvalidContextExtendFunctions(context);
        }

        [Test]
        public void TestPublicationsFileMissingNewerPublicationRecord()
        {
            // Check no publication found after current signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_New),
                PublicationsFile = new TestPublicationsFile()
            };

            Verify(context, VerificationResultCode.Na);
        }

        [Test]
        public void TestRfc3161SignatureOk()
        {
            // Check legacy signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok_With_Publication_Record),
                PublicationsFile = GetPublicationsFile(1401915603, "01B746442100F4C41F556B8D186FEF33A062234808BECF236A9EB8D23485CD4C3E"),
                ExtendedCalendarHashChain = GetExtendedCalendarHashChain()
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureOk()
        {
            // Check signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record),
                PublicationsFile = GetPublicationsFile(1439577241, "01B746442100F4C41F556B8D186FEF33A062234808BECF236A9EB8D23485CD4C3E"),
                ExtendedCalendarHashChain = GetExtendedCalendarHashChain()
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureWithHashMismatch()
        {
            // Test extender response calendar hash chain output hash and publications hash from publications file mismatch
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record),
                PublicationsFile = GetPublicationsFile(1439577241, "01A746442100F4C41F556B8D186FEF33A062234808BECF236A9EB8D23485CD4C3D"),
                ExtendedCalendarHashChain = GetExtendedCalendarHashChain()
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Pub01);
        }

        private static TestPublicationsFile GetPublicationsFile(ulong aggregationTime, string encodedPublicationHash)
        {
            return GetPublicationsFile(aggregationTime, 123456789, encodedPublicationHash);
        }

        private CalendarHashChain GetExtendedCalendarHashChain()
        {
            TlvTagBuilder builder = new TlvTagBuilder(Constants.CalendarHashChain.TagType, false, false);
            builder.AddChildTag(new IntegerTag(Constants.CalendarHashChain.PublicationTimeTagType, false, false, 1));
            builder.AddChildTag(new ImprintTag(Constants.CalendarHashChain.InputHashTagType, false, false,
                new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2"))));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Left, false, false, Base16.Decode("012E86118343FBFF0422986896C42363DB331EBDE356303C1DFC3F33B2FDC39B08")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("01319CD68E21755966EB91CFFE3AD2AAAEF141DA1A108B84595CA180260AE2DA0F")));
            return new CalendarHashChain(builder.BuildTag());
        }
    }
}