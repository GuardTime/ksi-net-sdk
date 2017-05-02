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

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation response payload.
    /// </summary>
    [Obsolete]
    public sealed class LegacyAggregationResponsePayload : SignRequestResponsePayload
    {
        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.AggregationResponsePayload.LegacyTagType;

        /// <summary>
        ///     Create aggregation response payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public LegacyAggregationResponsePayload(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.AggregationResponsePayload.ConfigTagType:
                    return GetRawTag(childTag);
                case Constants.AggregationResponsePayload.RequestAcknowledgmentTagType:
                    return GetRawTag(childTag);
                // following fields will be used to create KSI signature and parsed when creating the signature
                case Constants.AggregationHashChain.TagType:
                case Constants.CalendarHashChain.TagType:
                case Constants.PublicationRecord.TagTypeInSignature:
                case Constants.AggregationAuthenticationRecord.TagType:
                case Constants.CalendarAuthenticationRecord.TagType:
                    return childTag;
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

            if (tagCounter[Constants.AggregationResponsePayload.ConfigTagType] > 1)
            {
                throw new TlvException("Only one config is allowed in aggregation response payload.");
            }

            if (tagCounter[Constants.AggregationResponsePayload.RequestAcknowledgmentTagType] > 1)
            {
                throw new TlvException("Only one request acknowledgment is allowed in aggregation response payload.");
            }
        }
    }
}