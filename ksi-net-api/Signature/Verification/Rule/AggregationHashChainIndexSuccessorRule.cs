/*
 * Copyright 2013-2016 Guardtime, Inc.
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
using Guardtime.KSI.Utils;
using NLog;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// This rule checks that chain index of a aggregation hash chain is successor to it's parent aggregation hash chain index.
    /// </summary>
    public class AggregationHashChainIndexSuccessorRule : VerificationRule
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            ReadOnlyCollection<AggregationHashChain> aggregationHashChains = GetAggregationHashChains(GetSignature(context), true);
            ulong[] childChainIndex = null;
            ulong[] currentIndex = null;
            bool isValid = true;

            foreach (AggregationHashChain aggregationHashChain in aggregationHashChains)
            {
                currentIndex = aggregationHashChain.GetChainIndex();

                if (childChainIndex != null)
                {
                    if (childChainIndex.Length != currentIndex.Length + 1)
                    {
                        isValid = false;
                        break;
                    }

                    for (int i = 0; i < currentIndex.Length; i++)
                    {
                        if (currentIndex[i] != childChainIndex[i])
                        {
                            isValid = false;
                            break;
                        }
                    }
                }

                childChainIndex = currentIndex;
            }

            if (currentIndex != null && currentIndex.Length != 1)
            {
                Logger.Warn("Highest aggregation hash chain index length is not 1. Chain index: {0};", Util.ArrayToString(currentIndex));
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int12);
            }

            if (isValid)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            Logger.Warn("Chain index is not the successor to the parent aggregation hash chain index. Chain index: {0}; Parent chain index: {1}",
                Util.ArrayToString(childChainIndex), Util.ArrayToString(currentIndex));
            return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int12);
        }
    }
}