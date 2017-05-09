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

using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     Aggregation authentication record TLV element
    /// </summary>
    public sealed class AggregationAuthenticationRecord : CompositeTag
    {
        private IntegerTag _aggregationTime;
        private readonly List<IntegerTag> _chainIndex = new List<IntegerTag>();
        private ImprintTag _inputHash;

        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.AggregationAuthenticationRecord.TagType;

        /// <summary>
        ///     Create new aggregation authentication record TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationAuthenticationRecord(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.AggregationAuthenticationRecord.AggregationTimeTagType:
                    return _aggregationTime = GetIntegerTag(childTag);
                case Constants.AggregationAuthenticationRecord.ChainIndexTagType:
                    IntegerTag chainIndexTag = GetIntegerTag(childTag);
                    _chainIndex.Add(chainIndexTag);
                    return chainIndexTag;
                case Constants.AggregationAuthenticationRecord.InputHashTagType:
                    return _inputHash = GetImprintTag(childTag);
                case Constants.SignatureData.TagType:
                    return SignatureData = childTag as SignatureData ?? new SignatureData(childTag);
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

            if (tagCounter[Constants.AggregationAuthenticationRecord.AggregationTimeTagType] != 1)
            {
                throw new TlvException("Exactly one aggregation time must exist in aggregation authentication record.");
            }

            if (_chainIndex.Count == 0)
            {
                throw new TlvException("Chain indexes must exist in aggregation authentication record.");
            }

            if (tagCounter[Constants.AggregationAuthenticationRecord.InputHashTagType] != 1)
            {
                throw new TlvException("Exactly one input hash must exist in aggregation authentication record.");
            }

            if (tagCounter[Constants.SignatureData.TagType] != 1)
            {
                throw new TlvException("Exactly one signature data must exist in aggregation authentication record.");
            }
        }

        /// <summary>
        ///     Get aggregation time.
        /// </summary>
        public ulong AggregationTime => _aggregationTime.Value;

        /// <summary>
        ///     Get input hash.
        /// </summary>
        public DataHash InputHash => _inputHash.Value;

        /// <summary>
        ///     Get signature data.
        /// </summary>
        public SignatureData SignatureData { get; private set; }
    }
}