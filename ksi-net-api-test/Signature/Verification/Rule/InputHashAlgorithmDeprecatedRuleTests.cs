﻿/*
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
    public class InputHashAlgorithmDeprecatedRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            InputHashAlgorithmDeprecatedRule rule = new InputHashAlgorithmDeprecatedRule();

            // Argument null exception when no context
            Assert.Throws<ArgumentNullException>(delegate
            {
                rule.Verify(null);
            });
        }

        [Test]
        public void TestContextMissingSignature()
        {
            InputHashAlgorithmDeprecatedRule rule = new InputHashAlgorithmDeprecatedRule();

            // Verification exception on missing KSI signature 
            Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();
                rule.Verify(context);
            });
        }

        [Test]
        public void TestRfc3161SignatureWithOkInputHashAlgorithm()
        {
            InputHashAlgorithmDeprecatedRule rule = new InputHashAlgorithmDeprecatedRule();

            // Check legacy signature input hash algorithm
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Legacy_Ok), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestRfc3161SignatureWithOkSha1InputHashAlgorithm()
        {
            InputHashAlgorithmDeprecatedRule rule = new InputHashAlgorithmDeprecatedRule();

            // Check legacy signature with SHA1 input hash algorithm before deprecation time
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Rfc3161Record_Sha1InputHashAlgorithm_2016), FileMode.Open)
                )
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestRfc3161SignatureWithDeprecatedInputHashAlgorithm()
        {
            InputHashAlgorithmDeprecatedRule rule = new InputHashAlgorithmDeprecatedRule();

            // Check legacy signature with SHA1 input hash algorithm after deprecation time
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Rfc3161Record_Sha1InputHashAlgorithm_2017), FileMode.Open)
                )
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Int13, verificationResult.VerificationError);
            }
        }

        [Test]
        public void TestSignatureWithOkInputHashAlgorithm()
        {
            InputHashAlgorithmDeprecatedRule rule = new InputHashAlgorithmDeprecatedRule();

            // Check signature input hash algorithm
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestSignatureWithOkSha1InputHashAlgorithm()
        {
            InputHashAlgorithmDeprecatedRule rule = new InputHashAlgorithmDeprecatedRule();

            // Check signature with SHA1 input hash algorithm before deprecation time
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Sha1InputAlgorithm_2016), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestSignatureWithDeprecatedInputHashAlgorithm()
        {
            InputHashAlgorithmDeprecatedRule rule = new InputHashAlgorithmDeprecatedRule();

            // Check signature with SHA1 input hash algorithm after deprecation time
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Sha1InputAlgorithm_2017), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Int13, verificationResult.VerificationError);
            }
        }
    }
}