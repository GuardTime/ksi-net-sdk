/*
 * Copyright 2013-2016 Guardtime, Inc.
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

using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
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
            Assert.Throws<KsiException>(delegate
            {
                rule.Verify(null);
            });
        }

        [Test]
        public void TestContextMissingSignature()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            // Verification exception on missing KSI signature 
            Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();

                rule.Verify(context);
            });
        }

        [Test]
        public void TestSignatureWithoutAggregationHashChains()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            // Verification exception on missing KSI signature aggregation hash chain 
            Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new TestKsiSignature()
                };

                rule.Verify(context);
            });
        }

        /// <summary>
        /// Test metadata with padding value 01
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataWithPadding1()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = new KsiSignatureFactory().Create(
                    new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.AggregationHashChainMetadataWithPadding1), FileMode.Open))
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        /// <summary>
        /// Test metadata with padding value 0101
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataWithPadding2()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory().Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.AggregationHashChainMetadataWithPadding2), FileMode.Open))
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        /// <summary>
        /// Test metadata with padding not as first element
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataPaddingNotFirstFail()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory().Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.AggregationHashChainMetadataPaddingNotFirstFail), FileMode.Open))
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
        }

        /// <summary>
        /// Test metadata with padding encoded as tlv16
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataPaddingNotTlv8Fail()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory().Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.AggregationHashChainMetadataPaddingNotTlv8Fail), FileMode.Open))
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
        }

        /// <summary>
        /// Test metadata with padding: forward flag not set
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataPaddingNotForwardFail()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory().Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.AggregationHashChainMetadataPaddingNotForwardFail), FileMode.Open))
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
        }

        /// <summary>
        /// Test metadata with padding: non-critical flag not set
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataPaddingNotNonCriticalFail()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory().Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.AggregationHashChainMetadataPaddingNotNonCriticalFail), FileMode.Open))
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
        }

        /// <summary>
        /// Test metadata with padding: non-critical flag and forward flag not set
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataPaddingNotForwardNotNonCriticalFail()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory().Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.AggregationHashChainMetadataPaddingNotForwardNotNonCriticalFail), FileMode.Open))
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
        }

        /// <summary>
        /// Test metadata with padding: unknown padding value, "02"
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataUnknownPaddingValue1Fail()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory().Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.AggregationHashChainMetadataUnknownPaddingValue1Fail), FileMode.Open))
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
        }

        /// <summary>
        /// Test metadata with padding: unknown padding value, "0102"
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataUnknownPaddingValue2Fail()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory().Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.AggregationHashChainMetadataUnknownPaddingValue2Fail), FileMode.Open))
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
        }

        /// <summary>
        /// Test metadata with padding: unknown padding value, "010101"
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataUnknownPaddingValue3Fail()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory().Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.AggregationHashChainMetadataUnknownPaddingValue3Fail), FileMode.Open))
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
        }

        /// <summary>
        /// Test metadata with padding: invalid padding, "0101", but should be "01"
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataInvalidPaddingFail()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory().Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.AggregationHashChainMetadataInvalidPaddingFail), FileMode.Open))
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
        }

        /// <summary>
        /// Test metadata without padding
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataWithoutPadding()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory().Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.AggregationHashChainMetadataWithoutPadding), FileMode.Open))
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        /// <summary>
        /// Test metadata without padding: invalid first byte and length combination (possible to be interpreted as a valid imprint)
        /// </summary>
        [Test]
        public void TestAggregationHashChainMetadataWithoutPaddingFail()
        {
            AggregationHashChainMetadataRule rule = new AggregationHashChainMetadataRule();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory().Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.AggregationHashChainMetadataWithoutPaddingFail), FileMode.Open))
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
        }
    }
}