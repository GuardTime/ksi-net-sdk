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

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     Aggregation chain output result
    /// </summary>
    public class AggregationHashChainResult
    {
        /// <summary>
        ///     Create chain result from level and data hash.
        /// </summary>
        /// <param name="level">hash chain level</param>
        /// <param name="hash">output hash</param>
        public AggregationHashChainResult(ulong level, DataHash hash)
        {
            Level = level;
            Hash = hash;
        }

        /// <summary>
        ///     Get aggregation chain output hash
        /// </summary>
        public DataHash Hash { get; }

        /// <summary>
        ///     Get aggregation chain output hash level
        /// </summary>
        public ulong Level { get; }

        /// <summary>
        ///     Compare current object against another object.
        /// </summary>
        /// <param name="obj">object to compare with</param>
        /// <returns>true if objects are equal</returns>
        public override bool Equals(object obj)
        {
            AggregationHashChainResult a = obj as AggregationHashChainResult;

            // If parameter is null, return false. 
            if (ReferenceEquals(a, null))
            {
                return false;
            }

            if (ReferenceEquals(this, a))
            {
                return true;
            }

            // If run-time types are not exactly the same, return false. 
            if (GetType() != a.GetType())
            {
                return false;
            }

            return Hash == a.Hash && Level == a.Level;
        }

        /// <summary>
        ///     Get hash code of current object.
        /// </summary>
        /// <returns>hash code of current object</returns>
        public override int GetHashCode()
        {
            unchecked
            {
                return Level.GetHashCode() + Hash.GetHashCode();
            }
        }
    }
}