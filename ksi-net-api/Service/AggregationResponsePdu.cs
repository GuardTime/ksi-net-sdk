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

using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation response message PDU.
    /// </summary>
    public sealed class AggregationResponsePdu : KsiPdu
    {
        /// <summary>
        ///     Create aggregation response pdu TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationResponsePdu(ITlvTag tag) : base(tag)
        {
            CheckTagType(Constants.AggregationResponsePdu.TagType);

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.AggregationResponsePayload.TagType:
                        AggregationResponsePayload aggregationResponsePayload = new AggregationResponsePayload(childTag);
                        this[i] = aggregationResponsePayload;
                        Payloads.Add(aggregationResponsePayload);
                        break;
                    case Constants.AggregationErrorPayload.TagType:
                        AggregationErrorPayload aggregationErrorPayload = new AggregationErrorPayload(childTag);
                        this[i] = aggregationErrorPayload;
                        Payloads.Add(aggregationErrorPayload);
                        break;
                    case Constants.AggregationConfigResponsePayload.TagType:
                        AggregationConfigResponsePayload aggregationConfigResponsePayload = new AggregationConfigResponsePayload(childTag);
                        this[i] = aggregationConfigResponsePayload;
                        Payloads.Add(aggregationConfigResponsePayload);
                        break;
                    case Constants.KsiPduHeader.TagType:
                    case Constants.KsiPdu.MacTagType:
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }
        }

        /// <summary>
        /// Get aggregation response payload
        /// </summary>
        /// <param name="requestId">Request ID</param>
        /// <returns></returns>
        public AggregationResponsePayload GetAggregationResponsePayload(ulong requestId)
        {
            foreach (AggregationResponsePayload payload in GetPayloads<AggregationResponsePayload>())
            {
                if (payload.RequestId == requestId)
                {
                    return payload;
                }
            }

            return null;
        }

        /// <summary>
        /// Get aggregation error payload
        /// </summary>
        /// <returns></returns>
        public AggregationErrorPayload GetAggregationErrorPayload()
        {
            return GetPayload<AggregationErrorPayload>();
        }

        /// <summary>
        /// Get aggregation configuration response payload
        /// </summary>
        /// <returns></returns>
        public AggregationConfigResponsePayload GetAggregationConfigResponsePayload()
        {
            return GetPayload<AggregationConfigResponsePayload>();
        }
    }
}