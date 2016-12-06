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

using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extender configuration response payload.
    /// </summary>
    public sealed class ExtenderConfigResponsePayload : KsiPduPayload
    {
        private IntegerTag _maxRequests;
        private IntegerTag _calendarFirstTime;
        private IntegerTag _calendarLastTime;

        /// <summary>
        ///     Create extender configuration response payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public ExtenderConfigResponsePayload(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Validate the tag
        /// </summary>
        protected override void Validate()
        {
            CheckTagType(Constants.ExtenderConfigResponsePayload.TagType);
            base.Validate();

            int maxRequestsCount = 0;
            int calendarFirstTimeCount = 0;
            int calendarLastTimeCount = 0;

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.ExtenderConfigResponsePayload.MaxRequestsTagType:
                        this[i] = _maxRequests = new IntegerTag(childTag);
                        maxRequestsCount++;
                        break;
                    case Constants.ExtenderConfigResponsePayload.ParentUriTagType:
                        StringTag uriTag = new StringTag(childTag);
                        ParentsUris.Add(uriTag.Value);
                        this[i] = uriTag;
                        break;
                    case Constants.ExtenderConfigResponsePayload.CalendarFirstTimeTagType:
                        this[i] = _calendarFirstTime = new IntegerTag(childTag);
                        calendarFirstTimeCount++;
                        break;
                    case Constants.ExtenderConfigResponsePayload.CalendarLastTimeTagType:
                        this[i] = _calendarLastTime = new IntegerTag(childTag);
                        calendarLastTimeCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (maxRequestsCount > 1)
            {
                throw new TlvException("Only one max request tag is allowed in extender config response payload.");
            }

            if (calendarFirstTimeCount > 1)
            {
                throw new TlvException("Only one calendar first time tag is allowed in extender config response payload.");
            }

            if (calendarLastTimeCount > 1)
            {
                throw new TlvException("Only one calendar last time tag is allowed in extender config response payload.");
            }
        }

        /// <summary>
        /// Maximum number of requests the client is allowed to send within one second
        /// </summary>
        public ulong? MaxRequests => _maxRequests?.Value;

        /// <summary>
        /// Parent server URI (may be several parent servers)
        /// </summary>
        public IList<string> ParentsUris { get; } = new List<string>();

        /// <summary>
        /// Aggregation time of the oldest calendar record the extender has
        /// </summary>
        public ulong? CalendarFirstTime => _calendarFirstTime?.Value;

        /// <summary>
        /// Aggregation time of the newest calendar record the extender has
        /// </summary>
        public ulong? CalendarLastTime => _calendarLastTime?.Value;
    }
}