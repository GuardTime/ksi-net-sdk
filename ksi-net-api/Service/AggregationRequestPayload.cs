﻿/*
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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation request payload.
    /// </summary>
    public sealed class AggregationRequestPayload : KsiPduPayload
    {
        private readonly RawTag _config;
        private readonly ImprintTag _requestHash;
        private readonly IntegerTag _requestId;
        private readonly IntegerTag _requestLevel;

        /// <summary>
        ///     Create extend request payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationRequestPayload(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.AggregationRequestPayload.TagType)
            {
                throw new TlvException("Invalid aggregation request payload type(" + Type + ").");
            }

            int requestIdCount = 0;
            int requestHashCount = 0;
            int requestLevelCount = 0;
            int configCount = 0;

            foreach (ITlvTag childTag in this)
            {
                switch (childTag.Type)
                {
                    case Constants.AggregationRequestPayload.RequestIdTagType:
                        _requestId = new IntegerTag(childTag);
                        requestIdCount++;
                        break;
                    case Constants.AggregationRequestPayload.RequestHashTagType:
                        _requestHash = new ImprintTag(childTag);
                        requestHashCount++;
                        break;
                    case Constants.AggregationRequestPayload.RequestLevelTagType:
                        _requestLevel = new IntegerTag(childTag);
                        requestLevelCount++;
                        break;
                    case Constants.AggregationRequestPayload.ConfigTagType:
                        _config = new RawTag(childTag);
                        configCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (requestIdCount != 1)
            {
                throw new TlvException("Exactly one request id must exist in aggregation request payload.");
            }

            if (requestHashCount != 1)
            {
                throw new TlvException("Exactly one request hash must exist in aggregation request payload.");
            }

            if (requestLevelCount > 1)
            {
                throw new TlvException("Only one request level is allowed in aggregation request payload.");
            }

            if (configCount > 1)
            {
                throw new TlvException("Only one config tag is allowed in aggregation request payload.");
            }
        }

        /// <summary>
        ///     Create aggregation request payload from data hash.
        /// </summary>
        /// <param name="hash">data hash</param>
        public AggregationRequestPayload(DataHash hash) : base(Constants.AggregationRequestPayload.TagType, false, false, new ITlvTag[]
        {
            new IntegerTag(Constants.AggregationRequestPayload.RequestIdTagType, false, false, Util.GetRandomUnsignedLong()),
            new ImprintTag(Constants.AggregationRequestPayload.RequestHashTagType, false, false, hash)
        })
        {
            _requestId = (IntegerTag)this[0];
            _requestHash = (ImprintTag)this[1];
        }

        /// <summary>
        ///     Get request hash.
        /// </summary>
        public DataHash RequestHash => _requestHash.Value;

        /// <summary>
        ///     Is config requested.
        /// </summary>
        public bool IsConfigRequested => _config == null;

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