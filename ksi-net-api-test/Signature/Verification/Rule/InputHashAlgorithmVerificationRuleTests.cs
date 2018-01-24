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
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class InputHashAlgorithmVerificationRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new InputHashAlgorithmVerificationRule();

        [Test]
        public void TestSignatureWithoutDocumentHash()
        {
            // Check signature without document hash
            CreateSignatureAndVerify(Resources.KsiSignature_Ok, VerificationResultCode.Ok);
        }

        [Test]
        public void TestRfc3161SignatureWithoutDocumentHash()
        {
            // Check legacy signature without document hash
            CreateSignatureAndVerify(Resources.KsiSignature_Legacy_Ok, VerificationResultCode.Ok);
        }

        [Test]
        public void TestRfc3161SignatureWithCorrectInputHashAlgorithm()
        {
            // Check legacy signature input hash algorithm
            CreateSignatureAndVerify(Resources.KsiSignature_Ok, new DataHash(Base16.Decode("015466E3CBA14A843A5E93B78E3D6AB8D3491EDCAC7E06431CE1A7F49828C340C3")),
                VerificationResultCode.Ok);
        }

        [Test]
        public void TestRfc3161SignatureWithWrongInputHashAlgorithm()
        {
            // Check legacy signature input hash algorithm
            CreateSignatureAndVerify(Resources.KsiSignature_Legacy_Ok,
                new DataHash(Base16.Decode("045466E3CBA14A843A5E93B78E3D6AB8D3491EDCAC7E06431CE1A7F49828C340C3E1A7F49828C340C328C340C328C340C3")),
                VerificationResultCode.Fail, VerificationError.Gen04);
        }

        [Test]
        public void TestSignatureWithCorrectInputHashAlgorithm()
        {
            // Check signature input hash
            CreateSignatureAndVerify(Resources.KsiSignature_Ok, new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                VerificationResultCode.Ok);
        }

        [Test]
        public void TestSignatureWithWrongInputHashAlgorithm()
        {
            // Check signature invalid input hash algorithm
            CreateSignatureAndVerify(Resources.KsiSignature_Ok,
                new DataHash(Base16.Decode("0411A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772DE1A7F49828C340C328C340C328C340C3")),
                VerificationResultCode.Fail, VerificationError.Gen04);
        }

        [Test]
        public void TestSignatureWithWrongInputHashValue()
        {
            // Check signature invalid input hash value, but valid input hash algorithm
            CreateSignatureAndVerify(Resources.KsiSignature_Ok, new DataHash(Base16.Decode("0121A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                VerificationResultCode.Ok);
        }
    }
}