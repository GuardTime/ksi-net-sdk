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
    public class Rfc3161RecordHashAlgorithmDeprecatedRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            Rfc3161RecordHashAlgorithmDeprecatedRule rule = new Rfc3161RecordHashAlgorithmDeprecatedRule();

            // Argument null exception when no context
            Assert.Throws<ArgumentNullException>(delegate
            {
                rule.Verify(null);
            });
        }

        [Test]
        public void TestContextMissingSignature()
        {
            Rfc3161RecordHashAlgorithmDeprecatedRule rule = new Rfc3161RecordHashAlgorithmDeprecatedRule();

            // Verification exception on missing KSI signature 
            Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();
                rule.Verify(context);
            });
        }

        [Test]
        public void TestNonRfc3161Signature()
        {
            Rfc3161RecordHashAlgorithmDeprecatedRule rule = new Rfc3161RecordHashAlgorithmDeprecatedRule();

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
        public void TestRfc3161SignatureWithCorrectHashAlgorithms()
        {
            Rfc3161RecordHashAlgorithmDeprecatedRule rule = new Rfc3161RecordHashAlgorithmDeprecatedRule();
            // test using not deprecated hash algorithms
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
        public void TestRfc3161SignatureWithSha1TstInfoAlgorithm()
        {
            Rfc3161RecordHashAlgorithmDeprecatedRule rule = new Rfc3161RecordHashAlgorithmDeprecatedRule();

            // test using SHA1 hash TstInfo algorithm before deprecation time
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Rfc3161Record_Sha1TstInfoAlgorithm_2016), FileMode.Open))
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
        public void TestRfc3161SignatureWithDeprecatedTstInfoAlgorithm()
        {
            Rfc3161RecordHashAlgorithmDeprecatedRule rule = new Rfc3161RecordHashAlgorithmDeprecatedRule();

            // test using SHA1 hash TstInfo algorithm after deprecation time
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Rfc3161Record_Sha1TstInfoAlgorithm_2017), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Int14, verificationResult.VerificationError);
            }
        }

        [Test]
        public void TestRfc3161SignatureWithSha1SignedAttributesAlgorithm()
        {
            Rfc3161RecordHashAlgorithmDeprecatedRule rule = new Rfc3161RecordHashAlgorithmDeprecatedRule();

            // test using SHA1 hash SignedAttributes algorithm before deprecation time
            using (
                FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Rfc3161Record_Sha1SignedAttrAlgorithm_2016), FileMode.Open))
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
        public void TestRfc3161SignatureWithDeprecatedSignedAttributesAlgorithm()
        {
            Rfc3161RecordHashAlgorithmDeprecatedRule rule = new Rfc3161RecordHashAlgorithmDeprecatedRule();

            // test using SHA1 hash SignedAttributes algorithm after deprecation time
            using (
                FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Rfc3161Record_Sha1SignedAttrAlgorithm_2017), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Int14, verificationResult.VerificationError);
            }
        }
    }
}