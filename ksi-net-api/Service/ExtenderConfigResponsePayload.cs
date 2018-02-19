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

using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extender configuration response payload.
    /// </summary>
    public sealed class ExtenderConfigResponsePayload : PduPayload
    {
        private IntegerTag _maxRequests;
        private IntegerTag _calendarFirstTime;
        private IntegerTag _calendarLastTime;

        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.ExtenderConfigResponsePayload.TagType;

        /// <summary>
        ///     Create extender configuration response payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public ExtenderConfigResponsePayload(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.ExtenderConfigResponsePayload.MaxRequestsTagType:
                    return _maxRequests = GetIntegerTag(childTag);
                case Constants.ExtenderConfigResponsePayload.ParentUriTagType:
                    StringTag uriTag = GetStringTag(childTag);
                    ParentsUris.Add(uriTag.Value);
                    return uriTag;
                case Constants.ExtenderConfigResponsePayload.CalendarFirstTimeTagType:
                    return _calendarFirstTime = GetIntegerTag(childTag);
                case Constants.ExtenderConfigResponsePayload.CalendarLastTimeTagType:
                    return _calendarLastTime = GetIntegerTag(childTag);
                default:
                    return base.ParseChild(childTag);
            }
        }

        /// <summary>
        /// Validate the tag
        /// </summary>
        protected override void Validate(TagCounter tagCounter)
        {
            base.Validate(tagCounter);

            if (tagCounter[Constants.ExtenderConfigResponsePayload.MaxRequestsTagType] > 1)
            {
                throw new TlvException("Only one max requests tag is allowed in extender config response payload.");
            }

            if (tagCounter[Constants.ExtenderConfigResponsePayload.CalendarFirstTimeTagType] > 1)
            {
                throw new TlvException("Only one calendar first time tag is allowed in extender config response payload.");
            }

            if (tagCounter[Constants.ExtenderConfigResponsePayload.CalendarLastTimeTagType] > 1)
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