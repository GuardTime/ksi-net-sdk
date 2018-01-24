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
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class SignaturePublicationRecordPublicationTimeRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new SignaturePublicationRecordPublicationTimeRule();

        [Test]
        public void TestSignatureMissingCalendarHashChain()
        {
            TestSignatureMissingCalendarHashChain(new TestKsiSignature()
            {
                PublicationRecord = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record).PublicationRecord
            });
        }

        [Test]
        public void TestSignatureMissingPublicationRecord()
        {
            // Check signature without publication record
            CreateSignatureAndVerify(Resources.KsiSignature_Ok, VerificationResultCode.Ok);
        }

        [Test]
        public void TestRfc3161SignaturePublicationRecordTime()
        {
            // Check legacy signature with publication record
            CreateSignatureAndVerify(Resources.KsiSignature_Legacy_Ok_With_Publication_Record, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignaturePublicationRecordTime()
        {
            // Check signature with publication record
            CreateSignatureAndVerify(Resources.KsiSignature_Ok_With_Publication_Record, VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureInvalidPublicationRecordTime()
        {
            // Check invalid signature with invalid publication record
            CreateSignatureAndVerify(Resources.KsiSignature_Invalid_With_Invalid_Publication_Record_Time, VerificationResultCode.Fail, VerificationError.Int07);
        }
    }
}