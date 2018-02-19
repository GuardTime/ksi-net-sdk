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
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     Calendar authentication record TLV element
    /// </summary>
    public sealed class CalendarAuthenticationRecord : CompositeTag
    {
        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.CalendarAuthenticationRecord.TagType;

        /// <summary>
        ///     Create new calendar authentication record TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public CalendarAuthenticationRecord(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.PublicationData.TagType:
                    return PublicationData = childTag as PublicationData ?? new PublicationData(childTag);
                case Constants.SignatureData.TagType:
                    return SignatureData = childTag as SignatureData ?? new SignatureData(childTag);
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

            if (tagCounter[Constants.PublicationData.TagType] != 1)
            {
                throw new TlvException("Exactly one publication data must exist in calendar authentication record.");
            }

            if (tagCounter[Constants.SignatureData.TagType] != 1)
            {
                throw new TlvException("Exactly one signature data must exist in calendar authentication record.");
            }
        }

        /// <summary>
        ///     Get publication data.
        /// </summary>
        public PublicationData PublicationData { get; private set; }

        /// <summary>
        ///     Get signature data.
        /// </summary>
        public SignatureData SignatureData { get; private set; }
    }
}