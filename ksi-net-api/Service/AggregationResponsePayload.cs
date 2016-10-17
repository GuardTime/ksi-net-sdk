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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation response payload.
    /// </summary>
    public sealed class AggregationResponsePayload : KsiPduPayload
    {
        private readonly StringTag _errorMessage;
        private readonly IntegerTag _requestId;
        private readonly IntegerTag _status;

        /// <summary>
        ///     Create aggregation response payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationResponsePayload(ITlvTag tag) : base(tag)
        {
            CheckTagType(Constants.AggregationResponsePayload.TagType);

            int requestIdCount = 0;
            int statusCount = 0;
            int errorMessageCount = 0;

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.AggregationResponsePayload.RequestIdTagType:
                        this[i] = _requestId = new IntegerTag(childTag);
                        requestIdCount++;
                        break;
                    case Constants.KsiPduPayload.StatusTagType:
                        this[i] = _status = new IntegerTag(childTag);
                        statusCount++;
                        break;
                    case Constants.KsiPduPayload.ErrorMessageTagType:
                        this[i] = _errorMessage = new StringTag(childTag);
                        errorMessageCount++;
                        break;
                    case Constants.AggregationHashChain.TagType:
                    case Constants.CalendarHashChain.TagType:
                    case Constants.PublicationRecord.TagTypeInSignature:
                    case Constants.AggregationAuthenticationRecord.TagType:
                    case Constants.CalendarAuthenticationRecord.TagType:
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (requestIdCount != 1)
            {
                throw new TlvException("Exactly one request id must exist in aggregation response payload.");
            }

            // TODO: Should be mandatory element, but server side is broken.
            if (statusCount > 1)
            {
                throw new TlvException("Exactly one status code must exist in aggregation response payload.");
            }

            if (errorMessageCount > 1)
            {
                throw new TlvException("Only one error message is allowed in aggregation response payload.");
            }
        }

        /// <summary>
        ///     Get error message if it exists.
        /// </summary>
        public string ErrorMessage => _errorMessage?.Value;

        /// <summary>
        ///     Get request ID.
        /// </summary>
        public ulong RequestId => _requestId.Value;

        /// <summary>
        ///     Get status code.
        /// </summary>
        public ulong Status => _status?.Value ?? 0;
    }
}