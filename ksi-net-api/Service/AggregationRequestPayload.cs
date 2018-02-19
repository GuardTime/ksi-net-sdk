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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation request payload.
    /// </summary>
    public sealed class AggregationRequestPayload : PduPayload
    {
        private ImprintTag _requestHash;
        private IntegerTag _requestId;
        private IntegerTag _requestLevel;

        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.AggregationRequestPayload.TagType;

        /// <summary>
        ///     Create aggregation request payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationRequestPayload(ITlvTag tag) : base(tag)
        {
        }


        /// <summary>
        ///     Create aggregation request payload from data hash.
        /// </summary>
        /// <param name="requestId">Request ID</param>
        /// <param name="hash">data hash</param>
        public AggregationRequestPayload(ulong requestId, DataHash hash) : base(Constants.AggregationRequestPayload.TagType, false, false, new ITlvTag[]
        {
            new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, requestId),
            new ImprintTag(Constants.AggregationRequestPayload.RequestHashTagType, false, false, hash)
        })
        {

        }

        /// <summary>
        ///     Create aggregation request payload from data hash.
        /// </summary>
        /// <param name="requestId">Request ID</param>
        /// <param name="hash">data hash</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        public AggregationRequestPayload(ulong requestId, DataHash hash, uint level) : base(Constants.AggregationRequestPayload.TagType, false, false, new ITlvTag[]
        {
            new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, requestId),
            new ImprintTag(Constants.AggregationRequestPayload.RequestHashTagType, false, false, hash),
            new IntegerTag(Constants.AggregationRequestPayload.RequestLevelTagType, false, false, level)
        })
        {

        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.PduPayload.RequestIdTagType:
                    return _requestId = GetIntegerTag(childTag);
                case Constants.AggregationRequestPayload.RequestHashTagType:
                    return _requestHash = GetImprintTag(childTag);
                case Constants.AggregationRequestPayload.RequestLevelTagType:
                    return _requestLevel = GetIntegerTag(childTag);
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

            if (tagCounter[Constants.PduPayload.RequestIdTagType] != 1)
            {
                throw new TlvException("Exactly one request id must exist in aggregation request payload.");
            }

            if (tagCounter[Constants.AggregationRequestPayload.RequestHashTagType] != 1)
            {
                throw new TlvException("Exactly one request hash must exist in aggregation request payload.");
            }

            if (tagCounter[Constants.AggregationRequestPayload.RequestLevelTagType] > 1)
            {
                throw new TlvException("Only one request level is allowed in aggregation request payload.");
            }
        }


        /// <summary>
        ///     Get request hash.
        /// </summary>
        public DataHash RequestHash => _requestHash.Value;

        /// <summary>
        ///     Get request ID.
        /// </summary>
        public ulong RequestId => _requestId.Value;

        /// <summary>
        ///     Get request level if it exists.
        /// </summary>
        public ulong? RequestLevel => _requestLevel?.Value;
    }
}