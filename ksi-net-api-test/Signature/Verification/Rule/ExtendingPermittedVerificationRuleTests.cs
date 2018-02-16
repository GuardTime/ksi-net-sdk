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

using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class ExtendingPermittedVerificationRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new ExtendingPermittedVerificationRule();

        [Test]
        public override void TestContextMissingSignature()
        {
            // signature is not needed
        }

        [Test]
        public void TestExtendingPermitted()
        {
            TestVerificationContext context = new TestVerificationContext { IsExtendingAllowed = true };

            Verify(context, VerificationResultCode.Ok);
        }

        [Test]
        public void TestExtendingNotPermitted()
        {
            TestVerificationContext context = new TestVerificationContext { IsExtendingAllowed = false };
            Verify(context, VerificationResultCode.Na);
        }
    }
}