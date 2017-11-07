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

using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     This rule verifies document hash. If RFC3161 record is present then document hash must equal to RFC3161 record input hash. 
    ///     Otherwise document hash is compared to aggregation hash chain input hash.
    ///     If document hash is not provided then <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class DocumentHashVerificationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);
            DataHash documentHash = context.DocumentHash;

            if (documentHash == null)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            DataHash inputHash = signature.InputHash;

            if (documentHash != inputHash)
            {
                Logger.Debug("Invalid document hash. Expected {0}, found {1}", documentHash, inputHash);
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Gen01);
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}