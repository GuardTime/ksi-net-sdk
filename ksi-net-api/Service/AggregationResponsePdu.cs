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

using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation response message PDU.
    /// </summary>
    public sealed class AggregationResponsePdu : Pdu
    {
        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.AggregationResponsePdu.TagType;

        /// <summary>
        ///     Create aggregation response pdu TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationResponsePdu(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.AggregationResponsePayload.TagType:
                    AggregationResponsePayload aggregationResponsePayload = childTag as AggregationResponsePayload ?? new AggregationResponsePayload(childTag);
                    Payloads.Add(aggregationResponsePayload);
                    return aggregationResponsePayload;
                case Constants.ErrorPayload.TagType:
                    return ErrorPayload = childTag as AggregationErrorPayload ?? new AggregationErrorPayload(childTag);
                case Constants.AggregatorConfigResponsePayload.TagType:
                    AggregatorConfigResponsePayload aggregatorConfigResponsePayload = childTag as AggregatorConfigResponsePayload ?? new AggregatorConfigResponsePayload(childTag);
                    Payloads.Add(aggregatorConfigResponsePayload);
                    return aggregatorConfigResponsePayload;
                // not implemented yet, so just return the tag
                case Constants.AggregationAcknowledgmentResponsePayload.TagType:
                    return childTag;
                default:
                    return base.ParseChild(childTag);
            }
        }
    }
}