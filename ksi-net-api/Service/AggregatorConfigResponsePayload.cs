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
    ///     Aggregator configuration response payload.
    /// </summary>
    public sealed class AggregatorConfigResponsePayload : KsiPduPayload
    {
        private IntegerTag _aggregationPeriod;
        private IntegerTag _aggregationAlgorithm;
        private IntegerTag _maxLevel;
        private IntegerTag _maxRequests;

        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.AggregatorConfigResponsePayload.TagType;

        /// <summary>
        ///     Create aggregator configuration response payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregatorConfigResponsePayload(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.AggregatorConfigResponsePayload.MaxLevelTagType:
                    return _maxLevel = GetIntegerTag(childTag);
                case Constants.AggregatorConfigResponsePayload.AggregationAlgorithmTagType:
                    return _aggregationAlgorithm = GetIntegerTag(childTag);
                case Constants.AggregatorConfigResponsePayload.AggregationPeriodTagType:
                    return _aggregationPeriod = GetIntegerTag(childTag);
                case Constants.AggregatorConfigResponsePayload.MaxRequestsTagType:
                    return _maxRequests = GetIntegerTag(childTag);
                case Constants.AggregatorConfigResponsePayload.ParentUriTagType:
                    StringTag uriTag = GetStringTag(childTag);
                    ParentsUris.Add(uriTag.Value);
                    return uriTag;
                default:
                    return base.ParseChild(childTag);
            }
        }

        /// <summary>
        /// Validate the tag
        /// </summary>
        protected override void Validate(TagCounter tagCounter)
        {
            base.Validate(tagCounter);

            if (tagCounter[Constants.AggregatorConfigResponsePayload.MaxLevelTagType] > 1)
            {
                throw new TlvException("Only one max level tag is allowed in aggregator config response payload.");
            }

            if (tagCounter[Constants.AggregatorConfigResponsePayload.AggregationAlgorithmTagType] > 1)
            {
                throw new TlvException("Only one aggregation algorithm tag is allowed in aggregator config response payload.");
            }

            if (tagCounter[Constants.AggregatorConfigResponsePayload.AggregationPeriodTagType] > 1)
            {
                throw new TlvException("Only one aggregation period tag is allowed in aggregator config response payload.");
            }

            if (tagCounter[Constants.AggregatorConfigResponsePayload.MaxRequestsTagType] > 1)
            {
                throw new TlvException("Only one max requests tag is allowed in aggregator config response payload.");
            }
        }

        /// <summary>
        /// Maximum level value that the nodes in the client's aggregation tree are allowed to have
        /// </summary>
        public ulong? MaxLevel => _maxLevel?.Value;

        /// <summary>
        /// Identifier of the hash function that the client is recommended to use in its aggregation trees
        /// </summary>
        public ulong? AggregationAlgorithm => _aggregationAlgorithm?.Value;

        /// <summary>
        /// Recommended duration of client's aggregation round, in milliseconds
        /// </summary>
        public ulong? AggregationPeriod => _aggregationPeriod?.Value;

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