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

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     This rule verifies that given document hash level is not greater than the first link level correction of the first aggregation hash chain. 
    ///     In case RFC3161 signature the given document hash level must be 0.
    ///     If the level is equal to or less than expected then <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class DocumentHashLevelVerificationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);

            ulong levelCorrection = signature.IsRfc3161Signature ? 0 : signature.GetAggregationHashChains()[0].GetChainLinks()[0].LevelCorrection;

            return context.DocumentHashLevel > levelCorrection
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Gen03)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}