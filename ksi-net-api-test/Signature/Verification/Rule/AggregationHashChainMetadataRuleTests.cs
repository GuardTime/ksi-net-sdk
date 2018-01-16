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

using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class AggregationHashChainMetadataRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            // Argument null exception when no context
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                rule.Verify(null);
            });
            Assert.AreEqual("context", ex.ParamName);
        }

        [Test]
        public void TestContextMissingSignature()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            // Verification exception on missing KSI signature 
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();
                rule.Verify(context);
            });
            Assert.That(ex.Message, Does.StartWith("Invalid KSI signature in context: null"));
        }

        [Test]
        public void TestSignatureWithoutAggregationHashChain()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            // Verification exception on missing KSI signature aggregation hash chain 
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new TestKsiSignature()
                };

                rule.Verify(context);
            });
            Assert.That(ex.Message, Does.StartWith("Aggregation hash chains are missing from KSI signature"));
        }

        /// <summary>
        /// Test metadata with padding value 01
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataWithPadding1()
        {
            CreateAndVerify(Resources.AggregationHashChainMetadataWithPadding1, VerificationResultCode.Ok);
        }

        /// <summary>
        /// Test metadata with padding value 0101
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataWithPadding2()
        {
            CreateAndVerify(Resources.AggregationHashChainMetadataWithPadding2, VerificationResultCode.Ok);
        }

        /// <summary>
        /// Test metadata with padding not as first element
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataPaddingNotFirstFail()
        {
            CreateAndVerify(Resources.AggregationHashChainMetadataPaddingNotFirstFail, VerificationResultCode.Fail);
        }

        /// <summary>
        /// Test metadata with padding encoded as tlv16
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataPaddingNotTlv8Fail()
        {
            CreateAndVerify(Resources.AggregationHashChainMetadataPaddingNotTlv8Fail, VerificationResultCode.Fail);
        }

        /// <summary>
        /// Test metadata with padding: forward flag not set
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataPaddingNotForwardFail()
        {
            CreateAndVerify(Resources.AggregationHashChainMetadataPaddingNotForwardFail, VerificationResultCode.Fail);
        }

        /// <summary>
        /// Test metadata with padding: non-critical flag not set
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataPaddingNotNonCriticalFail()
        {
            CreateAndVerify(Resources.AggregationHashChainMetadataPaddingNotNonCriticalFail, VerificationResultCode.Fail);
        }

        /// <summary>
        /// Test metadata with padding: non-critical flag and forward flag not set
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataPaddingNotForwardNotNonCriticalFail()
        {
            CreateAndVerify(Resources.AggregationHashChainMetadataPaddingNotForwardNotNonCriticalFail, VerificationResultCode.Fail);
        }

        /// <summary>
        /// Test metadata with padding: unknown padding value, "02"
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataUnknownPaddingValue1Fail()
        {
            CreateAndVerify(Resources.AggregationHashChainMetadataUnknownPaddingValue1Fail, VerificationResultCode.Fail);
        }

        /// <summary>
        /// Test metadata with padding: unknown padding value, "0102"
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataUnknownPaddingValue2Fail()
        {
            CreateAndVerify(Resources.AggregationHashChainMetadataUnknownPaddingValue2Fail, VerificationResultCode.Fail);
        }

        /// <summary>
        /// Test metadata with padding: unknown padding value, "010101"
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataUnknownPaddingValue3Fail()
        {
            CreateAndVerify(Resources.AggregationHashChainMetadataUnknownPaddingValue3Fail, VerificationResultCode.Fail);
        }

        /// <summary>
        /// Test metadata with padding: invalid padding, "0101", but should be "01"
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataInvalidPaddingFail()
        {
            CreateAndVerify(Resources.AggregationHashChainMetadataInvalidPaddingFail, VerificationResultCode.Fail);
        }

        /// <summary>
        /// Test metadata without padding
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataWithoutPadding()
        {
            CreateAndVerify(Resources.AggregationHashChainMetadataWithoutPadding, VerificationResultCode.Ok);
        }

        /// <summary>
        /// Test metadata without padding: invalid first byte and length combination (possible to be interpreted as a valid imprint)
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataWithoutPaddingFail()
        {
            CreateAndVerify(Resources.AggregationHashChainMetadataWithoutPaddingFail, VerificationResultCode.Fail);
        }

        private static void CreateAndVerify(string path, VerificationResultCode expectedResultCode)
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(path)
            };

            Verify(rule, context, expectedResultCode, VerificationError.Int11.Code);
        }

        private static void Verify(AggregationHashChainMetadataRule rule, IVerificationContext context, VerificationResultCode expectedResultCode, string expectedErrorCode = null)
        {
            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(expectedResultCode, verificationResult.ResultCode, "Unexpected verification result code");
            if (expectedResultCode == VerificationResultCode.Fail)
            {
                Assert.AreEqual(expectedErrorCode, verificationResult.VerificationError.Code, "Unexpected verification error code");
            }
        }
    }
}