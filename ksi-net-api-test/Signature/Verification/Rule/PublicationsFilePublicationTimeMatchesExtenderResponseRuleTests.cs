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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Test.Publication;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class PublicationsFilePublicationTimeMatchesExtenderResponseRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new PublicationsFilePublicationTimeMatchesExtenderResponseRule();

        [Test]
        public void TestContextMissingPublicationsFile()
        {
            base.TestContextMissingPublicationsFile();
        }

        [Test]
        public void TestSignatureWithInvalidContextExtendFunctions()
        {
            // Check missing extended calendar chain
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok),
                PublicationsFile = GetPublicationsFile(1455478441, 1455494400),
            };

            TestSignatureWithInvalidContextExtendFunctions(context);
        }

        [Test]
        public void TestSignatureExtendMissingNewerPublication()
        {
            // Check no publication found after current signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_New),
                PublicationsFile = new TestPublicationsFile(),
            };

            DoesThrow<KsiVerificationException>(delegate
            {
                Rule.Verify(context);
            }, "No publication record found after given time in publications file");
        }

        [Test]
        public void TestRfc3161SignatureOk()
        {
            // Check legacy signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok),
                PublicationsFile = GetPublicationsFile(1401915603, 1439596800),
                ExtendedCalendarHashChain = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok_With_Publication_Record).CalendarHashChain
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureOk()
        {
            // Check signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok),
                PublicationsFile = GetPublicationsFile(1455478441, 1455494400),
                ExtendedCalendarHashChain = TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended).CalendarHashChain
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureWithInvalidExtendedCalendarHashChainPublicationTime()
        {
            // Check publication record publication time with invalid extended calendar publication time
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok),
                PublicationsFile = GetPublicationsFile(1455478441, 1455494401),
                ExtendedCalendarHashChain = TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended).CalendarHashChain
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Pub02);
        }

        [Test]
        public void TestSignatureWithInvalidExtendedCalendarHashChainRegistrationTime()
        {
            // Check signature aggregation time with invalid extended calendar registration time
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = new TestKsiSignature() { AggregationTime = 1455478440 },
                PublicationsFile = GetPublicationsFile(1455478440, 1455494400),
                ExtendedCalendarHashChain = TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended).CalendarHashChain
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Pub02);
        }

        private static TestPublicationsFile GetPublicationsFile(ulong aggregationTime, ulong publicationTime)
        {
            return GetPublicationsFile(aggregationTime, publicationTime, "01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2");
        }
    }
}