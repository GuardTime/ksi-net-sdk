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
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Integration
{
    [TestFixture]
    public class VerificationTests : IntegrationTests
    {
        [Test]
        public void VerifyWithVerificationContextNull()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new DefaultVerificationPolicy().Verify(null);
            });

            Assert.AreEqual("context", ex.ParamName);
        }

        [Test]
        public void VerifyWithSignatureNull()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new DefaultVerificationPolicy().Verify(new VerificationContext(null));
            });

            Assert.AreEqual("signature", ex.ParamName);
        }

        [Test]
        public void VerifyWithoutSignature()
        {
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                new DefaultVerificationPolicy().Verify(new VerificationContext());
            });

            Assert.That(ex.Message, Does.StartWith("Invalid KSI signature in context: null"));
        }

        [Test]
        public void VerifyWithoutKsiService()
        {
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                new DefaultVerificationPolicy().Verify(new VerificationContext(TestUtil.GetSignature())
                {
                    IsExtendingAllowed = true,
                    PublicationsFile = GetHttpKsiService().GetPublicationsFile()
                });
            });

            Assert.That(ex.Message, Does.StartWith("Invalid KSI service in context: null"));
        }

        [Test]
        public void Verify()
        {
            KsiService ksiService = GetHttpKsiService();
            VerificationResult result = new DefaultVerificationPolicy().Verify(new VerificationContext(TestUtil.GetSignature())
            {
                IsExtendingAllowed = true,
                KsiService = ksiService,
                PublicationsFile = ksiService.GetPublicationsFile()
            });

            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result");
        }
    }
}