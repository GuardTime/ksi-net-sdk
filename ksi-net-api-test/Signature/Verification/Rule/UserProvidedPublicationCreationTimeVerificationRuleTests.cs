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
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class UserProvidedPublicationCreationTimeVerificationRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            UserProvidedPublicationCreationTimeVerificationRule rule = new UserProvidedPublicationCreationTimeVerificationRule();

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
            UserProvidedPublicationCreationTimeVerificationRule rule = new UserProvidedPublicationCreationTimeVerificationRule();

            // Verification exception on missing KSI signature
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();

                rule.Verify(context);
            });
            Assert.That(ex.Message, Does.StartWith("Invalid KSI signature in context: null"));
        }

        [Test]
        public void TestSignatureWithAggregationChainOnly()
        {
            UserProvidedPublicationCreationTimeVerificationRule rule = new UserProvidedPublicationCreationTimeVerificationRule();

            // Check signature with aggregation chain only.
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_AggregationHashChain_Only),
                UserPublication = new PublicationData("AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUACP-GOGD6K")
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        [Test]
        public void TestSignatureWithoutContextUserPublication()
        {
            UserProvidedPublicationCreationTimeVerificationRule rule = new UserProvidedPublicationCreationTimeVerificationRule();

            // Check signature without user publication
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature()
            };

            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                rule.Verify(context);
            });
            Assert.That(ex.Message, Does.StartWith("Invalid user publication in context: null"));
        }

        [Test]
        public void TestRfc3161SignatureWithUserPublicationTime()
        {
            UserProvidedPublicationCreationTimeVerificationRule rule = new UserProvidedPublicationCreationTimeVerificationRule();

            // Check extended legacy signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok_With_Publication_Record),
                UserPublication = new PublicationData("AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUACP-GOGD6K")
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        [Test]
        public void TestSignatureWithUserPublicationTime()
        {
            UserProvidedPublicationCreationTimeVerificationRule rule = new UserProvidedPublicationCreationTimeVerificationRule();

            // Check extended signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record),
                UserPublication = new PublicationData("AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUACP-GOGD6K")
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        [Test]
        public void TestSignatureWithInvalidUserPublicationTime()
        {
            UserProvidedPublicationCreationTimeVerificationRule rule = new UserProvidedPublicationCreationTimeVerificationRule();

            // Check invalid signature
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_New),
                UserPublication = new PublicationData("AAAAAA-CVUWRI-AANGVK-SV7GJL-36LN65-AVJYZR-6XRZSL-HIMRH3-6GU7WR-YNRY7C-X2XEC3-YOVLRM")
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Na, verificationResult.ResultCode);
        }
    }
}