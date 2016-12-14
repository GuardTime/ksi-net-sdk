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
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation message PDU.
    /// </summary>
    [Obsolete]
    public sealed class LegacyAggregationPdu : LegacyPdu
    {
        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.LegacyAggregationPdu.TagType;

        /// <summary>
        ///     Create aggregation pdu TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        [Obsolete]
        public LegacyAggregationPdu(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        ///     Create aggregation pdu TLV element from KSI header and payload.
        /// </summary>
        /// <param name="header">PDU header</param>
        /// <param name="payload">aggregation payload</param>
        /// <param name="mac">pdu message hmac</param>
        [Obsolete]
        public LegacyAggregationPdu(PduHeader header, PduPayload payload, ImprintTag mac)
            : base(Constants.LegacyAggregationPdu.TagType, false, false, new ITlvTag[] { header, payload, mac })
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.AggregationRequestPayload.LegacyTagType:
                    return Payload = childTag as LegacyAggregationRequestPayload ?? new LegacyAggregationRequestPayload(childTag);
                case Constants.AggregationResponsePayload.LegacyTagType:
                    return Payload = childTag as LegacyAggregationResponsePayload ?? new LegacyAggregationResponsePayload(childTag);
                case Constants.LegacyAggregationErrorPayload.TagType:
                    return ErrorPayload = childTag as LegacyAggregationErrorPayload ?? new LegacyAggregationErrorPayload(childTag);
                default:
                    return base.ParseChild(childTag);
            }
        }
    }
}