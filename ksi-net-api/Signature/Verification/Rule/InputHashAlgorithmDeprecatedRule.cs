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
    ///     This rule verifies that input hash algorithm is not deprecated at aggregation time. If RFC3161 record is present then RFC3161 record input hash algorithm deprecation is checked.
    /// </summary>
    public sealed class InputHashAlgorithmDeprecatedRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);
            DataHash inputHash = signature.InputHash;

            if (inputHash.Algorithm.IsDeprecated(signature.AggregationTime))
            {
                Logger.Debug("Input hash algorithm was deprecated at aggregation time. Algorithm: {0}; Aggregation time: {1}", inputHash.Algorithm.Name, signature.AggregationTime);
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int13);
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}