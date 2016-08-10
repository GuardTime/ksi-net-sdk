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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation configuration response payload.
    /// </summary>
    public sealed class AggregationConfigResponsePayload : KsiPduPayload
    {
        private readonly IntegerTag _aggregationPeriod;
        private readonly IntegerTag _aggregationAlgorithm;
        private readonly IntegerTag _maxLevel;
        private readonly IntegerTag _maxRequests;

        /// <summary>
        ///     Create aggregation configuration response payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationConfigResponsePayload(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.AggregationConfigResponsePayload.TagType)
            {
                throw new TlvException("Invalid aggregation configuration response payload type(" + Type + ").");
            }

            int aggregationPeriodCount = 0;
            int aggregationAlgorithmCount = 0;
            int maxLevelCount = 0;
            int maxRequestsCount = 0;

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.AggregationConfigResponsePayload.AggregationPeriodTagType:
                        this[i] = _aggregationPeriod = new IntegerTag(childTag);
                        aggregationPeriodCount++;
                        break;
                    case Constants.AggregationConfigResponsePayload.AggregationAlgorithmTagType:
                        this[i] = _aggregationAlgorithm = new IntegerTag(childTag);
                        aggregationAlgorithmCount++;
                        break;
                    case Constants.AggregationConfigResponsePayload.MaxLevelTagType:
                        this[i] = _maxLevel = new IntegerTag(childTag);
                        maxLevelCount++;
                        break;
                    case Constants.AggregationConfigResponsePayload.MaxRequestsTagType:
                        this[i] = _maxRequests = new IntegerTag(childTag);
                        maxRequestsCount++;
                        break;
                    case Constants.AggregationConfigResponsePayload.ParentUriTagType:
                        StringTag uriTag = new StringTag(childTag);
                        ParentsUris.Add(uriTag.Value);
                        this[i] = uriTag;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (aggregationPeriodCount > 1)
            {
                throw new TlvException("Only one aggregation period tag is allowed in aggregation config response payload.");
            }

            if (aggregationAlgorithmCount > 1)
            {
                throw new TlvException("Only one aggregation algorithm tag is allowed in aggregation config response payload.");
            }

            if (maxLevelCount > 1)
            {
                throw new TlvException("Only one max level tag is allowed in aggregation config response payload.");
            }

            if (maxRequestsCount > 1)
            {
                throw new TlvException("Only one max requests tag is allowed in aggregation config response payload.");
            }
        }

        /// <summary>
        /// Recommended duration of client's aggregation round, in milliseconds
        /// </summary>
        public ulong? AggregationPeriod => _aggregationPeriod?.Value;

        /// <summary>
        /// Identifier of the hash function that the client is recommended to use in its aggregation trees
        /// </summary>
        public ulong? AggregationAlgorithm => _aggregationAlgorithm?.Value;

        /// <summary>
        /// Maximum level value that the nodes in the client's aggregation tree are allowed to have
        /// </summary>
        public ulong? MaxLevel => _maxLevel?.Value;

        /// <summary>
        /// Maximum number of requests the client is allowed to send within one parent server's aggregation round
        /// </summary>
        public ulong? MaxRequests => _maxRequests?.Value;

        /// <summary>
        /// Parent server URI (may be several parent servers)
        /// </summary>
        public IList<string> ParentsUris { get; } = new List<string>();
    }
}