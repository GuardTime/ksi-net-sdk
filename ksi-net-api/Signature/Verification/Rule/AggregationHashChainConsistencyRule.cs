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
    ///     Rule verifies if all aggregation hash chains are consistent. e.g. previous aggregation hash chain output hash
    ///     equals to current aggregation hash chain input hash.
    /// </summary>
    public sealed class AggregationHashChainConsistencyRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            ReadOnlyCollection<AggregationHashChain> aggregationHashChains = GetAggregationHashChains(GetSignature(context), true);
            AggregationHashChainResult chainResult = null;

            foreach (AggregationHashChain aggregationHashChain in aggregationHashChains)
            {
                if (chainResult == null)
                {
                    chainResult = new AggregationHashChainResult(0, aggregationHashChain.InputHash);
                }

                if (aggregationHashChain.InputHash != chainResult.Hash)
                {
                    Logger.Debug("Previous aggregation hash chain output hash {0} does not match current input hash {1}.", chainResult.Hash, aggregationHashChain.InputHash);
                    return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int01);
                }

                chainResult = aggregationHashChain.GetOutputHash(chainResult);
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}