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

using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation response payload.
    /// </summary>
    public sealed class AggregationResponsePayload : RequestResponsePayload
    {
        /// <summary>
        ///     Create aggregation response payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationResponsePayload(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Validate the tag
        /// </summary>
        protected override void Validate()
        {
            CheckTagType(Constants.AggregationResponsePayload.TagType);

            base.Validate();

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    // following fields will be checked in the base class
                    case Constants.KsiPduPayload.RequestIdTagType:
                    case Constants.KsiPduPayload.StatusTagType:
                    case Constants.KsiPduPayload.ErrorMessageTagType:
                        break;
                    // following fields will be used to create KSI signature
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
        }
    }
}