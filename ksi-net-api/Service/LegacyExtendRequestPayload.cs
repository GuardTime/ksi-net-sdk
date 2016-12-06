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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extend request payload.
    /// </summary>
    [Obsolete]
    public sealed class LegacyExtendRequestPayload : KsiPduPayload
    {
        private IntegerTag _aggregationTime;
        private IntegerTag _publicationTime;
        private IntegerTag _requestId;

        /// <summary>
        ///     Create extend request payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public LegacyExtendRequestPayload(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Validate the tag
        /// </summary>
        protected override void Validate()
        {
            CheckTagType(Constants.ExtendRequestPayload.LegacyTagType);

            base.Validate();

            int requestIdCount = 0;
            int aggregationTimeCount = 0;
            int publicationTimeCount = 0;

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.KsiPduPayload.RequestIdTagType:
                        this[i] = _requestId = new IntegerTag(childTag);
                        requestIdCount++;
                        break;
                    case Constants.ExtendRequestPayload.AggregationTimeTagType:
                        this[i] = _aggregationTime = new IntegerTag(childTag);
                        aggregationTimeCount++;
                        break;
                    case Constants.ExtendRequestPayload.PublicationTimeTagType:
                        this[i] = _publicationTime = new IntegerTag(childTag);
                        publicationTimeCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (requestIdCount != 1)
            {
                throw new TlvException("Exactly one request id must exist in extend request payload.");
            }

            if (aggregationTimeCount != 1)
            {
                throw new TlvException("Exactly one aggregation time must exist in extend request payload.");
            }

            if (publicationTimeCount > 1)
            {
                throw new TlvException("Only one publication time is allowed in extend request payload.");
            }
        }

        /// <summary>
        ///     Create extend request payload from aggregation time and publication time.
        /// </summary>
        /// <param name="requestId">Request ID</param>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        public LegacyExtendRequestPayload(ulong requestId, ulong aggregationTime, ulong publicationTime)
            : base(Constants.ExtendRequestPayload.LegacyTagType, false, false, new ITlvTag[]
            {
                new IntegerTag(Constants.KsiPduPayload.RequestIdTagType, false, false, requestId),
                new IntegerTag(Constants.ExtendRequestPayload.AggregationTimeTagType, false, false, aggregationTime),
                new IntegerTag(Constants.ExtendRequestPayload.PublicationTimeTagType, false, false, publicationTime)
            })
        {
            _requestId = (IntegerTag)this[0];
            _aggregationTime = (IntegerTag)this[1];
            _publicationTime = (IntegerTag)this[2];
        }

        /// <summary>
        ///     Create extend request payload from aggregation time.
        /// </summary>
        /// <param name="requestId">Request ID</param>
        /// <param name="aggregationTime">aggregation time</param>
        public LegacyExtendRequestPayload(ulong requestId, ulong aggregationTime) : base(Constants.ExtendRequestPayload.LegacyTagType, false, false, new ITlvTag[]
        {
            new IntegerTag(Constants.KsiPduPayload.RequestIdTagType, false, false, requestId),
            new IntegerTag(Constants.ExtendRequestPayload.AggregationTimeTagType, false, false, aggregationTime)
        })
        {
            _requestId = (IntegerTag)this[0];
            _aggregationTime = (IntegerTag)this[1];
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