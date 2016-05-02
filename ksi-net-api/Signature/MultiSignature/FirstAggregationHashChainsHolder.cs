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

using System.Collections.Generic;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Signature.MultiSignature
{
    /// <summary>
    /// Class for holding first level aggreagtion hash chains in multi-signature.
    /// </summary>
    public class FirstAggregationHashChainsHolder : MultiValueDataHolder<DataHash, AggregationHashChain>
    {
        /// <summary>
        /// Add an aggregation hash chain. Elements under the same key will be sorted by aggregation time.
        /// </summary>
        public override void Add(AggregationHashChain aggregationHashChain)
        {
            DataHash key = aggregationHashChain.InputHash;
            if (ContainsKey(key))
            {
                ulong[] chainIndex = aggregationHashChain.GetChainIndex();

                foreach (AggregationHashChain existingAggregationHashChain in Get(key))
                {
                    if (existingAggregationHashChain.AggregationTime == aggregationHashChain.AggregationTime &&
                        Util.IsArrayEqual(existingAggregationHashChain.GetChainIndex(), chainIndex))
                    {
                        return;
                    }
                }

                Get(key).Add(aggregationHashChain);
                Get(key).Sort(new AggregationTimeComparer());
            }
            else
            {
                Add(key, new List<AggregationHashChain>() { aggregationHashChain });
            }
        }

        /// <summary>
        /// Comparer for sorting by aggregation time.
        /// </summary>
        private class AggregationTimeComparer : IComparer<AggregationHashChain>
        {
            public int Compare(AggregationHashChain value1, AggregationHashChain value2)
            {
                return value1.AggregationTime.CompareTo(value2.AggregationTime);
            }
        }
    }
}