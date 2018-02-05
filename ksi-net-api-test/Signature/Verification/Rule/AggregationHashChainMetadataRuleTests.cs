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
    public class AggregationHashChainMetadataTests : RuleTestsBase
    {
        public override VerificationRule Rule => new AggregationHashChainMetadataRule();

        [Test]
        public void TestSignatureMissingAggregationHashChain()
        {
            TestSignatureMissingAggregationHashChain(null, true);
        }

        /// <summary>
        /// Test metadata with padding value 01
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataWithPadding1()
        {
            CreateSignatureAndVerify(Resources.AggregationHashChainMetadataWithPadding1, VerificationResultCode.Ok);
        }

        /// <summary>
        /// Test metadata with padding value 0101
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataWithPadding2()
        {
            CreateSignatureAndVerify(Resources.AggregationHashChainMetadataWithPadding2, VerificationResultCode.Ok);
        }

        /// <summary>
        /// Test metadata with padding not as first element
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataPaddingNotFirstFail()
        {
            CreateSignatureAndVerify(Resources.AggregationHashChainMetadataPaddingNotFirstFail, VerificationResultCode.Fail, VerificationError.Int11);
        }

        /// <summary>
        /// Test metadata with padding encoded as tlv16
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataPaddingNotTlv8Fail()
        {
            CreateSignatureAndVerify(Resources.AggregationHashChainMetadataPaddingNotTlv8Fail, VerificationResultCode.Fail, VerificationError.Int11);
        }

        /// <summary>
        /// Test metadata with padding: forward flag not set
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataPaddingNotForwardFail()
        {
            CreateSignatureAndVerify(Resources.AggregationHashChainMetadataPaddingNotForwardFail, VerificationResultCode.Fail, VerificationError.Int11);
        }

        /// <summary>
        /// Test metadata with padding: non-critical flag not set
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataPaddingNotNonCriticalFail()
        {
            CreateSignatureAndVerify(Resources.AggregationHashChainMetadataPaddingNotNonCriticalFail, VerificationResultCode.Fail, VerificationError.Int11);
        }

        /// <summary>
        /// Test metadata with padding: non-critical flag and forward flag not set
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataPaddingNotForwardNotNonCriticalFail()
        {
            CreateSignatureAndVerify(Resources.AggregationHashChainMetadataPaddingNotForwardNotNonCriticalFail, VerificationResultCode.Fail, VerificationError.Int11);
        }

        /// <summary>
        /// Test metadata with padding: unknown padding value, "02"
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataUnknownPaddingValue1Fail()
        {
            CreateSignatureAndVerify(Resources.AggregationHashChainMetadataUnknownPaddingValue1Fail, VerificationResultCode.Fail, VerificationError.Int11);
        }

        /// <summary>
        /// Test metadata with padding: unknown padding value, "0102"
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataUnknownPaddingValue2Fail()
        {
            CreateSignatureAndVerify(Resources.AggregationHashChainMetadataUnknownPaddingValue2Fail, VerificationResultCode.Fail, VerificationError.Int11);
        }

        /// <summary>
        /// Test metadata with padding: unknown padding value, "010101"
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataUnknownPaddingValue3Fail()
        {
            CreateSignatureAndVerify(Resources.AggregationHashChainMetadataUnknownPaddingValue3Fail, VerificationResultCode.Fail, VerificationError.Int11);
        }

        /// <summary>
        /// Test metadata with padding: invalid padding, "0101", but should be "01"
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataInvalidPaddingFail()
        {
            CreateSignatureAndVerify(Resources.AggregationHashChainMetadataInvalidPaddingFail, VerificationResultCode.Fail, VerificationError.Int11);
        }

        /// <summary>
        /// Test metadata without padding
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataWithoutPadding()
        {
            CreateSignatureAndVerify(Resources.AggregationHashChainMetadataWithoutPadding, VerificationResultCode.Ok);
        }

        /// <summary>
        /// Test metadata without padding and with invalid hash algorithm id as first metadata content byte.
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataWithoutPaddingWithInvalidHashAlgorithmId()
        {
            CreateSignatureAndVerify(Resources.AggregationHashChainMetadataWithoutPaddingWithInvalidAlgorithm, VerificationResultCode.Ok);
        }

        /// <summary>
        /// Test metadata without padding: invalid first byte and length combination (possible to be interpreted as a valid imprint)
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataWithoutPaddingFail()
        {
            CreateSignatureAndVerify(Resources.AggregationHashChainMetadataWithoutPaddingFail, VerificationResultCode.Fail, VerificationError.Int11);
        }
    }
}