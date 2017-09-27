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
    public class CalendarHashChainAlgorithmObsoleteTests
    {
        [Test]
        public void TestMissingContext()
        {
            CalendarHashChainAlgorithmObsoleteRule rule = new CalendarHashChainAlgorithmObsoleteRule();

            // Argument null exception when no context
            Assert.Throws<ArgumentNullException>(delegate
            {
                rule.Verify(null);
            });
        }

        [Test]
        public void TestContextMissingSignature()
        {
            CalendarHashChainAlgorithmObsoleteRule rule = new CalendarHashChainAlgorithmObsoleteRule();

            // Verification exception on missing KSI signature 
            Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();
                rule.Verify(context);
            });
        }

        [Test]
        public void TestSignatureWithOkAlgorithms()
        {
            CalendarHashChainAlgorithmObsoleteRule rule = new CalendarHashChainAlgorithmObsoleteRule();

            // Check with calendar hash chains that use valid hash algorithms
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
        public void TestSignatureWithOkSha1RightLinkAlgorithm()
        {
            CalendarHashChainAlgorithmObsoleteRule rule = new CalendarHashChainAlgorithmObsoleteRule();

            // Check signature with SHA1 calendar right link hash algorithm before obsolete time
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Sha1CalendarRightLinkAlgorithm_2016), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        /// <summary>
        /// This test is used to test calendar right link hash algorithms after obsolete date.
        /// </summary>
        [Test]
        public void TestSignatureWithObsoleteRightLinkAlgorithm()
        {
            // We cannot really use this test until a hash algorithm gets obsolete date.          
            // Until then the test can be used if 1467331200 is added as obsolete date to SHA-1 algorithm
            return;

            CalendarHashChainAlgorithmObsoleteRule rule = new CalendarHashChainAlgorithmObsoleteRule();

            // Check signature with SHA1 calendar right link algorithm after obsolete time
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Sha1CalendarRightLinkAlgorithm_2017), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Int16, verificationResult.VerificationError);
            }
        }
    }
}