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
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extension response payload.
    /// </summary>
    public sealed class ExtendResponsePayload : KsiPduPayload
    {
        private readonly StringTag _errorMessage;
        private readonly IntegerTag _lastTime;
        private readonly IntegerTag _requestId;
        private readonly IntegerTag _status;

        /// <summary>
        ///     Create extend response payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public ExtendResponsePayload(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.ExtendResponsePayload.TagType)
            {
                throw new TlvException("Invalid extend response payload type(" + Type + ").");
            }

            int requestIdCount = 0;
            int statusCount = 0;
            int errorMessageCount = 0;
            int lastTimeCount = 0;
            int calendarHashChainCount = 0;

            foreach (ITlvTag childTag in this)
            {
                switch (childTag.Type)
                {
                    case Constants.ExtendResponsePayload.RequestIdTagType:
                        _requestId = new IntegerTag(childTag);
                        requestIdCount++;
                        break;
                    case Constants.KsiPduPayload.StatusTagType:
                        _status = new IntegerTag(childTag);
                        statusCount++;
                        break;
                    case Constants.KsiPduPayload.ErrorMessageTagType:
                        _errorMessage = new StringTag(childTag);
                        errorMessageCount++;
                        break;
                    case Constants.ExtendResponsePayload.LastTimeTagType:
                        _lastTime = new IntegerTag(childTag);
                        lastTimeCount++;
                        break;
                    case Constants.CalendarHashChain.TagType:
                        CalendarHashChain = new CalendarHashChain(childTag);
                        calendarHashChainCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (requestIdCount != 1)
            {
                throw new TlvException("Exactly one request id must exist in extend response payload.");
            }

            if (statusCount != 1)
            {
                throw new TlvException("Exactly one status code must exist in extend response payload.");
            }

            if (errorMessageCount > 1)
            {
                throw new TlvException("Only one error message is allowed in extend response payload.");
            }

            if (lastTimeCount > 1)
            {
                throw new TlvException("Only one last time is allowed in extend response payload.");
            }

            if (_status.Value == 0 && calendarHashChainCount != 1)
            {
                throw new TlvException("Exactly one calendar hash chain must exist in extend response payload.");
            }

            if (_status.Value != 0 && calendarHashChainCount != 0)
            {
                throw new TlvException("Calendar hash chain should be missing when error occurs in extend response payload.");
            }
        }

        /// <summary>
        ///     Get calendar hash chain.
        /// </summary>
        public CalendarHashChain CalendarHashChain { get; }

        /// <summary>
        ///     Get error message if it exists.
        /// </summary>
        public string ErrorMessage => _errorMessage?.Value;

        /// <summary>
        ///     Get last time if it exists.
        /// </summary>
        public ulong? LastTime => _lastTime?.Value;

        /// <summary>
        ///     Get request ID.
        /// </summary>
        public ulong RequestId => _requestId.Value;

        /// <summary>
        ///     Get status code.
        /// </summary>
        public ulong Status => _status.Value;
    }
}