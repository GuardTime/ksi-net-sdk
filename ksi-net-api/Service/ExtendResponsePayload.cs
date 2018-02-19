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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extend response payload.
    /// </summary>
    public sealed class ExtendResponsePayload : RequestResponsePayload
    {
        private IntegerTag _calendarLastTime;

        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.ExtendResponsePayload.TagType;

        /// <summary>
        ///     Create extend response payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public ExtendResponsePayload(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.ExtendResponsePayload.CalendarLastTimeTagType:
                    return _calendarLastTime = GetIntegerTag(childTag);
                case Constants.CalendarHashChain.TagType:
                    return CalendarHashChain = childTag as CalendarHashChain ?? new CalendarHashChain(childTag);
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

            if (tagCounter[Constants.ExtendResponsePayload.CalendarLastTimeTagType] > 1)
            {
                throw new TlvException("Only one calendar last time is allowed in extend response payload.");
            }

            if (Status == 0 && tagCounter[Constants.CalendarHashChain.TagType] != 1)
            {
                throw new TlvException("Exactly one calendar hash chain must exist in extend response payload.");
            }
        }

        /// <summary>
        ///     Get calendar hash chain.
        /// </summary>
        public CalendarHashChain CalendarHashChain { get; private set; }

        /// <summary>
        ///     Get aggregation time of the newest calendar record the extender has
        /// </summary>
        public ulong? CalendarLastTime => _calendarLastTime?.Value;
    }
}