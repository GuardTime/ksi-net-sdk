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

using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Verifies that aggregation hash chains use hash algorithms that were not deprecated at the aggregation time.
    /// </summary>
    public sealed class AggregationHashChainAlgorithmDeprecatedRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            ReadOnlyCollection<AggregationHashChain> aggregationHashChains = GetAggregationHashChains(GetSignature(context), true);

            foreach (AggregationHashChain aggregationHashChain in aggregationHashChains)
            {
                if (aggregationHashChain.AggregationAlgorithm.IsDeprecated(aggregationHashChain.AggregationTime))
                {
                    Logger.Debug("Aggregation hash chain aggregation algorithm was deprecated at aggregation time. Algorithm: {0}; Aggregation time: {1}",
                        aggregationHashChain.AggregationAlgorithm.Name, aggregationHashChain.AggregationTime);
                    return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int15);
                }
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}