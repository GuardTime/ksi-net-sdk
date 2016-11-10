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
    ///     KSI PDU response payload. Contains additional payload fields.
    /// </summary>
    public abstract class ResponsePayloadExtended : ResponsePayload
    {
        private readonly IntegerTag _requestId;

        /// <summary>
        ///     Create KSI PDU extended response payload TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <param name="expectedTagType">expected tag type</param>
        protected ResponsePayloadExtended(ITlvTag tag, uint expectedTagType) : base(tag, expectedTagType)
        {
            int requestIdCount = 0;

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.KsiPduPayload.RequestIdTagType:
                        this[i] = _requestId = new IntegerTag(childTag);
                        requestIdCount++;
                        break;
                }
            }

            if (requestIdCount != 1)
            {
                throw new TlvException("Exactly one request id must exist in response payload.");
            }
        }

        /// <summary>
        ///     Get request ID.
        /// </summary>
        public ulong RequestId => _requestId.Value;
    }
}