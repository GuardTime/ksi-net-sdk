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

using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that shape of the aggregation hash chain matches with chain index.
    /// </summary>
    public class AggregationHashChainShapeRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            ReadOnlyCollection<AggregationHashChain> aggregationHashChains = GetAggregationHashChains(GetSignature(context), true);

            foreach (AggregationHashChain aggregationHashChain in aggregationHashChains)
            {
                ulong[] chainIndex = aggregationHashChain.GetChainIndex();
                ulong calculatedValue = aggregationHashChain.CalcLocationPointer();
                ulong valueInChain = chainIndex[chainIndex.Length - 1];

                if (valueInChain != calculatedValue)
                {
                    Logger.Debug("The shape of the aggregation hash chain does not match with the chain index. Calculated location pointer: {0}; Value in chain: {1}",
                        calculatedValue, valueInChain);
                    return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int10);
                }
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}