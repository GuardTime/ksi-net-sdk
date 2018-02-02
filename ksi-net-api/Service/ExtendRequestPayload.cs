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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extend request payload.
    /// </summary>
    public sealed class ExtendRequestPayload : PduPayload
    {
        private IntegerTag _aggregationTime;
        private IntegerTag _publicationTime;
        private IntegerTag _requestId;

        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.ExtendRequestPayload.TagType;

        /// <summary>
        ///     Create extend request payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public ExtendRequestPayload(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        ///     Create extend request payload from aggregation time and publication time.
        /// </summary>
        /// <param name="requestId">Request ID</param>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        public ExtendRequestPayload(ulong requestId, ulong aggregationTime, ulong publicationTime) : base(Constants.ExtendRequestPayload.TagType, false, false, new ITlvTag[]
        {
            new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, requestId),
            new IntegerTag(Constants.ExtendRequestPayload.AggregationTimeTagType, false, false, aggregationTime),
            new IntegerTag(Constants.ExtendRequestPayload.PublicationTimeTagType, false, false, publicationTime)
        })
        {
        }

        /// <summary>
        ///     Create extend request payload from aggregation time.
        /// </summary>
        /// <param name="requestId">Request ID</param>
        /// <param name="aggregationTime">aggregation time</param>
        public ExtendRequestPayload(ulong requestId, ulong aggregationTime) : base(Constants.ExtendRequestPayload.TagType, false, false, new ITlvTag[]
        {
            new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, requestId),
            new IntegerTag(Constants.ExtendRequestPayload.AggregationTimeTagType, false, false, aggregationTime)
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
                case Constants.ExtendRequestPayload.AggregationTimeTagType:
                    return _aggregationTime = GetIntegerTag(childTag);
                case Constants.ExtendRequestPayload.PublicationTimeTagType:
                    return _publicationTime = GetIntegerTag(childTag);
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
                throw new TlvException("Exactly one request id must exist in extend request payload.");
            }

            if (tagCounter[Constants.ExtendRequestPayload.AggregationTimeTagType] != 1)
            {
                throw new TlvException("Exactly one aggregation time must exist in extend request payload.");
            }

            if (tagCounter[Constants.ExtendRequestPayload.PublicationTimeTagType] > 1)
            {
                throw new TlvException("Only one publication time is allowed in extend request payload.");
            }
        }

        /// <summary>
        ///     Get request ID.
        /// </summary>
        public ulong RequestId => _requestId.Value;

        /// <summary>
        ///     Get aggregation time.
        /// </summary>
        public ulong AggregationTime => _aggregationTime.Value;

        /// <summary>
        ///     Get publication time if exists otherwise null.
        /// </summary>
        public ulong? PublicationTime => _publicationTime?.Value;
    }
}