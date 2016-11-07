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

using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation request message PDU.
    /// </summary>
    public sealed class AggregationRequestPdu : KsiPdu
    {
        /// <summary>
        ///     Create aggregation request pdu TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationRequestPdu(ITlvTag tag) : base(tag)
        {
            CheckTagType(Constants.AggregationRequestPdu.TagType);

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.AggregationRequestPayload.TagType:
                        AggregationRequestPayload aggregationRequestPayload = new AggregationRequestPayload(childTag);
                        this[i] = aggregationRequestPayload;
                        Payloads.Add(aggregationRequestPayload);
                        break;
                    case Constants.AggregationConfigRequestPayload.TagType:
                        AggregationConfigRequestPayload aggregationConfigRequestPayload = new AggregationConfigRequestPayload(childTag);
                        this[i] = aggregationConfigRequestPayload;
                        Payloads.Add(aggregationConfigRequestPayload);
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
        ///     Create aggregation request pdu TLV element from KSI header and payload.
        /// </summary>
        /// <param name="header">KSI PDU header</param>
        /// <param name="payload">aggregation payload</param>
        /// <param name="hmacAlgorithm">HMAC algorithm</param>
        /// <param name="key">hmac key</param>
        public AggregationRequestPdu(KsiPduHeader header, KsiPduPayload payload, HashAlgorithm hmacAlgorithm, byte[] key)
            : base(Constants.AggregationRequestPdu.TagType, header, payload, hmacAlgorithm, key)
        {
            Payloads.Add(payload);
        }
    }
}