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

using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation request message PDU.
    /// </summary>
    public sealed class AggregationRequestPdu : Pdu
    {
        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.AggregationRequestPdu.TagType;

        /// <summary>
        ///     Create aggregation request pdu TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationRequestPdu(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        ///     Create aggregation request pdu TLV element from KSI header and payload.
        /// </summary>
        /// <param name="header">PDU header</param>
        /// <param name="payload">aggregation payload</param>
        /// <param name="macAlgorithm">MAC algorithm</param>
        /// <param name="key">hmac key</param>
        public AggregationRequestPdu(PduHeader header, PduPayload payload, HashAlgorithm macAlgorithm, byte[] key)
            : base(Constants.AggregationRequestPdu.TagType, header, payload, macAlgorithm, key)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.AggregationRequestPayload.TagType:
                    AggregationRequestPayload aggregationRequestPayload = childTag as AggregationRequestPayload ?? new AggregationRequestPayload(childTag);
                    Payloads.Add(aggregationRequestPayload);
                    return aggregationRequestPayload;
                case Constants.AggregatorConfigRequestPayload.TagType:
                    AggregatorConfigRequestPayload aggregatorConfigRequestPayload = childTag as AggregatorConfigRequestPayload ?? new AggregatorConfigRequestPayload(childTag);
                    Payloads.Add(aggregatorConfigRequestPayload);
                    return aggregatorConfigRequestPayload;
                default:
                    return base.ParseChild(childTag);
            }
        }
    }
}