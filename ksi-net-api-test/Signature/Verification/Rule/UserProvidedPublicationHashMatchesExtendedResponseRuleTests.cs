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
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class UserProvidedPublicationHashMatchesExtendedResponseRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new UserProvidedPublicationHashMatchesExtendedResponseRule();

        [Test]
        public override void TestContextMissingSignature()
        {
            // signature is not needed
        }

        [Test]
        public void TestContextMissingUserPublication()
        {
            base.TestContextMissingUserPublication();
        }

        [Test]
        public void TestSignatureWithInvalidContextExtendFunctions()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                UserPublication = GetUserPublication("015A7F7D504E5E146EE34E64F831A6B6C7D65291EAEC46FACF60ED6ACA72BCB2DE")
            };

            TestSignatureWithInvalidContextExtendFunctions(context);
        }

        [Test]
        public void TestHashesMatch()
        {
            // Check signature with publication record
            TestVerificationContext context = new TestVerificationContext()
            {
                ExtendedCalendarHashChain = GetExtendedCalendarHashChain(),
                UserPublication = GetUserPublication("015A7F7D504E5E146EE34E64F831A6B6C7D65291EAEC46FACF60ED6ACA72BCB2DE")
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestHashesMismatch()
        {
            // publication hashes mismatch
            TestVerificationContext context = new TestVerificationContext()
            {
                ExtendedCalendarHashChain = GetExtendedCalendarHashChain(),
                UserPublication = GetUserPublication("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Pub01);
        }

        private static PublicationData GetUserPublication(string encodedPublicationHash)
        {
            return new PublicationData(123456789, new DataHash(Base16.Decode(encodedPublicationHash)));
        }

        private CalendarHashChain GetExtendedCalendarHashChain()
        {
            TlvTagBuilder builder = new TlvTagBuilder(Constants.CalendarHashChain.TagType, false, false);
            builder.AddChildTag(new IntegerTag(Constants.CalendarHashChain.PublicationTimeTagType, false, false, 1));
            builder.AddChildTag(new ImprintTag(Constants.CalendarHashChain.InputHashTagType, false, false,
                new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2"))));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Left, false, false, Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")));
            return new CalendarHashChain(builder.BuildTag());
        }
    }
}