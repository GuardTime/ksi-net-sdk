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
    /// Class for holding RFC3161 records in multi-signature.
    /// </summary>
    public class Rfc3161RecordHolder : MultiValueDataHolder<DataHash, Rfc3161Record>
    {
        /// <summary>
        /// Add an RFC3161 record. Elements under the same key will be sorted by aggregation time.
        /// </summary>
        public override void Add(Rfc3161Record rfc3161Record)
        {
            DataHash key = rfc3161Record.InputHash;

            if (ContainsKey(key))
            {
                ulong[] chainIndex = rfc3161Record.GetChainIndex();

                foreach (Rfc3161Record existingRfc3161Record in Get(key))
                {
                    if (existingRfc3161Record.AggregationTime == rfc3161Record.AggregationTime &&
                        Util.IsArrayEqual(existingRfc3161Record.GetChainIndex(), chainIndex))
                    {
                        return;
                    }
                }

                Get(key).Add(rfc3161Record);
                Get(key).Sort(new AggregationTimeComparer());
            }
            else
            {
                Add(key, new List<Rfc3161Record>() { rfc3161Record });
            }
        }

        /// <summary>
        /// Comparer for sorting by aggregation time.
        /// </summary>
        private class AggregationTimeComparer : IComparer<Rfc3161Record>
        {
            public int Compare(Rfc3161Record value1, Rfc3161Record value2)
            {
                return value1.AggregationTime.CompareTo(value2.AggregationTime);
            }
        }
    }
}