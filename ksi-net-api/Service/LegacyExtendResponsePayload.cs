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
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extend response payload.
    /// </summary>
    [Obsolete]
    public sealed class LegacyExtendResponsePayload : ResponsePayloadExtended
    {
        private readonly IntegerTag _calendarLastTime;

        /// <summary>
        ///     Create extend response payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public LegacyExtendResponsePayload(ITlvTag tag) : base(tag, Constants.ExtendResponsePayload.LegacyTagType)
        {
            int calendarLastTimeCount = 0;
            int calendarHashChainCount = 0;

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.KsiPduPayload.RequestIdTagType:
                    case Constants.KsiPduPayload.StatusTagType:
                    case Constants.KsiPduPayload.ErrorMessageTagType:
                        break;
                    case Constants.ExtendResponsePayload.LastTimeTagType:
                    case Constants.ExtendResponsePayload.CalendarLastTimeTagType:
                        this[i] = _calendarLastTime = new IntegerTag(childTag);
                        calendarLastTimeCount++;
                        break;
                    case Constants.CalendarHashChain.TagType:
                        this[i] = CalendarHashChain = new CalendarHashChain(childTag);
                        calendarHashChainCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (calendarLastTimeCount > 1)
            {
                throw new TlvException("Only one calendar last time is allowed in extend response payload.");
            }

            if (Status == 0 && calendarHashChainCount != 1)
            {
                throw new TlvException("Exactly one calendar hash chain must exist in extend response payload.");
            }
        }

        /// <summary>
        ///     Get calendar hash chain.
        /// </summary>
        public CalendarHashChain CalendarHashChain { get; }

        /// <summary>
        ///     Get aggregation time of the newest calendar record the extender has
        /// </summary>
        public ulong? CalendarLastTime => _calendarLastTime?.Value;
    }
}