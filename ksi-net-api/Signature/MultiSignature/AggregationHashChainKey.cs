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

using System;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Signature.MultiSignature
{
    /// <summary>
    /// Key object for holding aggregation hash chains.
    /// </summary>
    public class AggregationHashChainKey : IEquatable<AggregationHashChainKey>
    {
        /// <summary>
        /// Creates new aggregation hash chain key instance
        /// </summary>
        /// <param name="aggregationTime">Aggregation time</param>
        /// <param name="chainIndex">Chain index</param>
        public AggregationHashChainKey(ulong aggregationTime, ulong[] chainIndex)
        {
            AggregationTime = aggregationTime;
            ChainIndex = chainIndex;

            EqualityCheckValue = aggregationTime;

            foreach (ulong i in chainIndex)
            {
                EqualityCheckValue += i;
            }
        }

        /// <summary>
        /// Aggregation time
        /// </summary>
        public ulong AggregationTime { get; }

        /// <summary>
        /// Chain index
        /// </summary>
        public ulong[] ChainIndex { get; }

        /// <summary>
        /// Holds equality check value used for comparing instances. Used for boosting Equals method performance.
        /// </summary>
        private ulong EqualityCheckValue { get; }

        /// <summary>
        /// Convert aggregation hash chain key to string
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return string.Format("Time: {0}; Index: {1}", AggregationTime, string.Join(", ", Array.ConvertAll(ChainIndex, Convert.ToString)));
        }

        /// <summary>
        /// Compare current key against another key. Keys are equal when aggregation times are equal and chain indexes match.
        /// </summary>
        /// <param name="valueToCompare">Key to compare against</param>
        /// <returns>True if keys are equal</returns>
        public bool Equals(AggregationHashChainKey valueToCompare)
        {
            if (EqualityCheckValue != valueToCompare.EqualityCheckValue)
            {
                return false;
            }

            if (AggregationTime != valueToCompare.AggregationTime)
            {
                return false;
            }

            return Util.IsArrayEqual(ChainIndex, valueToCompare.ChainIndex);
        }

        /// <summary>
        /// Get hash code
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return (int)AggregationTime + ChainIndex.Length;
        }
    }
}