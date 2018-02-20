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
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class DocumentHashLevelVerificationRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new DocumentHashLevelVerificationRule();

        [Test]
        public void TestDocumentHashWithNoLevel()
        {
            CreateSignatureAndVerify(Resources.KsiSignature_Ok, new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                VerificationResultCode.Ok);
        }

        [Test]
        public void TestDocumentHashLevelZero()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(),
                DocumentHashLevel = 0,
                DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"))
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestDocumentHashLevelInvalid()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(),
                DocumentHashLevel = 1,
                DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"))
            };
            Verify(context, VerificationResultCode.Fail, VerificationError.Gen03);
        }

        [Test]
        public void TestDocumentHashLevel3()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_LevelCorrection3),
                DocumentHashLevel = 3,
                DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"))
            };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestDocumentHashLevel3Invalid()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_LevelCorrection3),
                DocumentHashLevel = 4,
                DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"))
            };
            Verify(context, VerificationResultCode.Fail, VerificationError.Gen03);
        }

        [Test]
        public void TestRfc3161DocumentHashLevelZero()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok),
                DocumentHashLevel = 0,
                DocumentHash =
                    new DataHash(Base16.Decode("015466E3CBA14A843A5E93B78E3D6AB8D3491EDCAC7E06431CE1A7F49828C340C3"))
            };
            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestRfc3161DocumentHashLevelNotZero()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok),
                DocumentHashLevel = 1,
                DocumentHash =
                    new DataHash(Base16.Decode("015466E3CBA14A843A5E93B78E3D6AB8D3491EDCAC7E06431CE1A7F49828C340C3"))
            };
            Verify(context, VerificationResultCode.Fail, VerificationError.Gen03);
        }
    }
}