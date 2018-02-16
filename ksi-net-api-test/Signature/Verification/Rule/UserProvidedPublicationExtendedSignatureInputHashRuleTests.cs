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
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class UserProvidedPublicationExtendedSignatureInputHashRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new UserProvidedPublicationExtendedSignatureInputHashRule();

        /// <summary>
        /// Verification exception on missing KSI signature 
        /// </summary>
        [Test]
        public override void TestContextMissingSignature()
        {
            TestContextMissingSignature(new TestVerificationContext()
            {
                ExtendedCalendarHashChain = GetExtendedCalendarHashChain("01145C6CDA9F901A65C0B3C09896675928E1A85977280BF65C0A638C8A47BB358A"),
                UserPublication = GetUserPublication()
            });
        }

        [Test]
        public void TestContextMissingUserPublication()
        {
            base.TestContextMissingUserPublication();
        }

        [Test]
        public void TestSignatureWithInvalidContextExtendFunctions()
        {
            // Check invalid extended calendar chain from context extension function
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(),
                UserPublication = GetUserPublication()
            };

            TestSignatureWithInvalidContextExtendFunctions(context);
        }

        [Test]
        public void TestRfc3161SignatureUserPublicationHash()
        {
            // Check legacy signature with publication record
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok),
                ExtendedCalendarHashChain = GetExtendedCalendarHashChain("01145C6CDA9F901A65C0B3C09896675928E1A85977280BF65C0A638C8A47BB358A"),
                UserPublication = GetUserPublication()
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureUserPublicationHash()
        {
            // Check signature with publication record
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok),
                ExtendedCalendarHashChain = GetExtendedCalendarHashChain("012C8149F374FDDCD5443456BC7E8FFA310B7FE090DAA98C0980B81EC2407FD013"),
                UserPublication = GetUserPublication()
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureInvalidAggregationRootHash()
        {
            // Check invalid signature with invalid root hash
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok),
                ExtendedCalendarHashChain = GetExtendedCalendarHashChain("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2"),
                UserPublication = GetUserPublication()
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Pub03);
        }

        private static PublicationData GetUserPublication()
        {
            return new PublicationData("AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUACP-GOGD6K");
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