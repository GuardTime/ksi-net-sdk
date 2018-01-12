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
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class AggregationHashChainIndexSuccessorRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            AggregationHashChainIndexSuccessorRule rule = new AggregationHashChainIndexSuccessorRule();

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
            AggregationHashChainIndexSuccessorRule rule = new AggregationHashChainIndexSuccessorRule();

            // Verification exception on missing KSI signature 
            Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();

                rule.Verify(context);
            });
        }

        [Test]
        public void TestSignatureWithoutAggregationHashChain()
        {
            AggregationHashChainIndexSuccessorRule rule = new AggregationHashChainIndexSuccessorRule();

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

        [Test]
        public void TestRfc3161SignatureAggregationHashChainIndexSuccessor()
        {
            AggregationHashChainIndexSuccessorRule rule = new AggregationHashChainIndexSuccessorRule();

            // Check legacy signature for aggregation hash chain index match against previous chain index
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Legacy_Ok), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestSignatureAggregationHashChainIndexSuccessor()
        {
            AggregationHashChainIndexSuccessorRule rule = new AggregationHashChainIndexSuccessorRule();

            // Check signature for aggregation hash chain index match against previous chain index
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestInvalidSignatureAggregationHashChainIndexSuccessor()
        {
            AggregationHashChainIndexSuccessorRule rule = new AggregationHashChainIndexSuccessorRule();

            // Check invalid signature for aggregation hash chain index mismatch against previous chain index (Chain index: 11, 879, 475, 3951, 3; Parent chain index: 11, 879, 475, 255)
            using (FileStream stream =
                new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Invalid_Aggregation_Chain_Index_Mismatch_Prev), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Int12, verificationResult.VerificationError);
            }
        }

        [Test]
        public void TestInvalidSignatureAggregationHashChainIndexSuccessor2()
        {
            AggregationHashChainIndexSuccessorRule rule = new AggregationHashChainIndexSuccessorRule();

            // Check invalid signature for aggregation hash chain index mismatch against previous chain index (chain index equals parent chain index. Chain index: 11, 879, 475, 3951; Parent chain index: 11, 879, 475, 3951)
            using (FileStream stream =
                new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Invalid_Aggregation_Chain_Index_Mismatch_Prev2), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Int12, verificationResult.VerificationError);
            }
        }

        [Test]
        public void TestInvalidSignatureFirstAggregationHashChainIndexLength()
        {
            AggregationHashChainIndexSuccessorRule rule = new AggregationHashChainIndexSuccessorRule();

            // First aggregation hash chain index length is not 1
            using (FileStream stream =
                new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Invalid_First_Aggregation_Chain_Index_Length), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Int12, verificationResult.VerificationError);
            }
        }
    }
}