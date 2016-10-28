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
    public class Rfc3161RecordChainIndexRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            Rfc3161RecordChainIndexRule rule = new Rfc3161RecordChainIndexRule();

            // Argument null exception when no context
            Assert.Throws<KsiException>(delegate
            {
                rule.Verify(null);
            });
        }

        [Test]
        public void TestContextMissingSignature()
        {
            Rfc3161RecordChainIndexRule rule = new Rfc3161RecordChainIndexRule();

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
            Rfc3161RecordChainIndexRule rule = new Rfc3161RecordChainIndexRule();

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Legacy_Ok), FileMode.Open))
            {
                Rfc3161Record rfc3161Record = new KsiSignatureFactory().Create(stream).Rfc3161Record;

                // Verification exception on missing KSI signature aggregation hash chain 
                Assert.Throws<KsiVerificationException>(delegate
                {
                    TestVerificationContext context = new TestVerificationContext()
                    {
                        Signature = new TestKsiSignature() { Rfc3161Record = rfc3161Record }
                    };

                    rule.Verify(context);
                });
            }
        }

        [Test]
        public void TestRfc3161RecordChainIndex()
        {
            Rfc3161RecordChainIndexRule rule = new Rfc3161RecordChainIndexRule();
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Legacy_Ok), FileMode.Open))
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
        public void TestInvalidRfc3161RecordChainIndex()
        {
            Rfc3161RecordChainIndexRule rule = new Rfc3161RecordChainIndexRule();

            using (FileStream stream =
                new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Invalid_Rfc3161_Chain_Index_Mismatch), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream)
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Int10, verificationResult.VerificationError);
            }
        }
    }
}