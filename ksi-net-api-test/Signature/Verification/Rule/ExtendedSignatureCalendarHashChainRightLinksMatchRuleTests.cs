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

using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class ExtendedSignatureCalendarHashChainRightLinksMatchRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new ExtendedSignatureCalendarHashChainRightLinksMatchRule();

        [Test]
        public void TestSignatureMissingCalendarHashChain()
        {
            // Check signature without calendar chain
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_AggregationHashChain_Only),
                ExtendedCalendarHashChain = TestUtil.GetSignature().CalendarHashChain
            };
            TestSignatureMissingCalendarHashChain(context);
        }

        [Test]
        public void TestSignatureWithInvalidContextExtendFunctions()
        {
            // Check invalid extended calendar chain when service returns null
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature()
            };

            TestSignatureWithInvalidContextExtendFunctions(context);
        }

        /// <summary>
        /// Check legacy signature right links with extended chain. 
        /// </summary>
        [Test]
        public void TestRfc3161SignatureRightLinks()
        {
            KsiSignature signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok);
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = signature,
                ExtendedCalendarHashChain = signature.CalendarHashChain
            };

            Verify(context, VerificationResultCode.Ok);
        }

        /// <summary>
        /// Check signature right links with extended chain. 
        /// </summary>
        [Test]
        public void TestSignatureRightLinks()
        {
            KsiSignature signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended);
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = signature,
                ExtendedCalendarHashChain = signature.CalendarHashChain
            };

            Verify(context, VerificationResultCode.Ok);
        }

        /// <summary>
        /// Check extended signature calendar hash chain against extended calendar hash chain (not all elements are equal)
        /// </summary>
        [Test]
        public void TestSignatureExtendedCalendarHashChainElementDiffers()
        {
            KsiSignature signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended);
            TlvTagBuilder builder = GetBuilder(signature);
            builder.ReplaceChildTag(signature.CalendarHashChain[signature.CalendarHashChain.Count - 1],
                new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")));

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = signature,
                ExtendedCalendarHashChain = new CalendarHashChain(builder.BuildTag())
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Cal04);
        }

        /// <summary>
        /// Check extended signature calendar hash chain against extended calendar hash chain (chain lengths differ)
        /// </summary>
        [Test]
        public void TestSignatureExtendedCalendarHashChainLengthDiffers()
        {
            KsiSignature signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended);
            TlvTagBuilder builder = GetBuilder(signature);
            builder.RemoveChildTag(signature.CalendarHashChain[signature.CalendarHashChain.Count - 1]);

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = signature,
                ExtendedCalendarHashChain = new CalendarHashChain(builder.BuildTag())
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Cal04);
        }

        private static TlvTagBuilder GetBuilder(KsiSignature signature)
        {
            TlvTagBuilder builder = new TlvTagBuilder(Constants.CalendarHashChain.TagType, false, false);
            foreach (ITlvTag child in   signature.CalendarHashChain)
            {
                CalendarHashChain.Link link = child as CalendarHashChain.Link;
                if (link != null && link.Type == (uint)LinkDirection.Right)
                {
                    // add a left link, this does not make the verification to fail.
                    builder.AddChildTag(new RawTag((uint)LinkDirection.Left, false, false, Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")));
                }

                builder.AddChildTag(child);
            }
            return builder;
        }
    }
}