/*
 * Copyright 2013-2018 Guardtime, Inc.
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
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Integration
{
    [TestFixture]
    public class KsiVerificationTests : IntegrationTests
    {
        /// <summary>
        /// Signature is verified using DefaultVerificationPolicy. 
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void Verify(Ksi ksi)
        {
            VerificationResult result = ksi.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok));
            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual(nameof(DefaultVerificationPolicy), result.RuleName, "Unexpected policy used.");
        }

        /// <summary>
        /// Verifying null signature. 
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void VerifyWithSignatureNull(Ksi ksi)
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                ksi.Verify(null);
            });

            Assert.AreEqual("ksiSignature", ex.ParamName);
        }

        /// <summary>
        /// Verifying signature null and publications file not null.
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void VerifyWithSignatureNull2(Ksi ksi)
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                ksi.Verify(null, null, TestUtil.GetPublicationsFile());
            });

            Assert.AreEqual("ksiSignature", ex.ParamName);
        }

        /// <summary>
        /// Verifying with policy null. 
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void VerifyWithVerificationPolicyNull(Ksi ksi)
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                ksi.Verify((VerificationPolicy)null, null);
            });

            Assert.AreEqual("policy", ex.ParamName);
        }

        /// <summary>
        /// Verifying with verification context null. 
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void VerifyWithVerificationContextNull(Ksi ksi)
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                ksi.Verify(new DefaultVerificationPolicy(), null);
            });

            Assert.AreEqual("context", ex.ParamName);
        }

        /// <summary>
        /// Verifying with publications file null. 
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void VerifyWithPublicationsFileNull(Ksi ksi)
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                ksi.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok), null, null);
            });

            Assert.AreEqual("publicationsFile", ex.ParamName);
        }

        /// <summary>
        /// Signature is verified using DefaultVerificationPolicy with document hash. 
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void VerifyWithDocumentHash(Ksi ksi)
        {
            VerificationResult result = ksi.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok),
                new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual(nameof(DefaultVerificationPolicy), result.RuleName, "Unexpected policy used.");
        }

        /// <summary>
        /// Signature is verified using DefaultVerificationPolicy with extending allowed. 
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void VerifyWithExtendingAllowed(Ksi ksi)
        {
            VerificationResult result = ksi.Verify(new DefaultVerificationPolicy(), new VerificationContext(TestUtil.GetSignature(Resources.KsiSignature_Ok))
            {
                PublicationsFile = ksi.GetPublicationsFile(),
                IsExtendingAllowed = true
            });
            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual(nameof(DefaultVerificationPolicy), result.RuleName, "Unexpected policy used.");
        }

        /// <summary>
        /// Signature is verified using DefaultVerificationPolicy with publications file. 
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void VerifyWithPublicationsFile(Ksi ksi)
        {
            VerificationResult result = ksi.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok), null, TestUtil.GetPublicationsFile());
            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual(nameof(DefaultVerificationPolicy), result.RuleName, "Unexpected policy used.");
        }

        /// <summary>
        /// Signature is verified using DefaultVerificationPolicy with document hash and publications file. 
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void VerifyWithDocumentHashAndPublicationsFile(Ksi ksi)
        {
            VerificationResult result = ksi.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok),
                new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")), TestUtil.GetPublicationsFile());
            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual(nameof(DefaultVerificationPolicy), result.RuleName, "Unexpected policy used.");
        }

        /// <summary>
        /// Signature verification failed using DefaultVerificationPolicy with document hash. 
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void VerifyFailWithInvalidDocumentHash(Ksi ksi)
        {
            VerificationResult result = ksi.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok),
                new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")));
            Assert.AreEqual(VerificationResultCode.Fail, result.ResultCode);
            Assert.AreEqual(VerificationError.Gen01, result.VerificationError);
            Assert.AreEqual(nameof(DefaultVerificationPolicy), result.RuleName, "Unexpected policy used.");
        }

        /// <summary>
        /// Freshly created signature is verified using DefaultVerificationPolicy. 
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void VerifyNewSignature(Ksi ksi)
        {
            IKsiSignature signature = ksi.Sign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
            VerificationResult result = ksi.Verify(signature);
            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual(nameof(DefaultVerificationPolicy), result.RuleName, "Unexpected policy used.");
        }

        /// <summary>
        /// Freshly created signature is verified using DefaultVerificationPolicy with document hash. 
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void VerifyNewSignatureWithDocumentHash(Ksi ksi)
        {
            DataHash documentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"));
            IKsiSignature signature = ksi.Sign(documentHash);
            VerificationResult result = ksi.Verify(signature, documentHash);
            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual(nameof(DefaultVerificationPolicy), result.RuleName, "Unexpected policy used.");
        }

        /// <summary>
        /// Freshly created signature is verified using DefaultVerificationPolicy with publications file. 
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void VerifyNewSignatureWithPublicationsFile(Ksi ksi)
        {
            DataHash documentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"));
            IKsiSignature signature = ksi.Sign(documentHash);
            VerificationResult result = ksi.Verify(signature, null, ksi.GetPublicationsFile());
            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual(nameof(DefaultVerificationPolicy), result.RuleName, "Unexpected policy used.");
        }
    }
}