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

using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Verifies that RFC3161 record output hash algorithm was not deprecated at the aggregation time. 
    ///     If RFC3161 record is not present then <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public class Rfc3161RecordOutputHashAlgorithmDeprecatedRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);

            if (!signature.IsRfc3161Signature)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            AggregationHashChain aggregationHashChain = GetAggregationHashChains(signature, false)[0];
            HashAlgorithm hashAlgorithm = aggregationHashChain.InputHash.Algorithm;
            ulong aggregationTime = aggregationHashChain.AggregationTime;

            if (hashAlgorithm.IsDeprecated(aggregationTime))
            {
                Logger.Debug("RFC3161 output hash algorithm was deprecated at aggregation time. Algorithm: {0}; Aggregation time: {1}", hashAlgorithm.Name, aggregationTime);
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int17);
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}