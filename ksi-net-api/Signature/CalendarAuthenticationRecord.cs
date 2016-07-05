﻿/*
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
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     Calendar authentication record TLV element
    /// </summary>
    public sealed class CalendarAuthenticationRecord : CompositeTag
    {
        /// <summary>
        ///     Create new calendar authentication record TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public CalendarAuthenticationRecord(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.CalendarAuthenticationRecord.TagType)
            {
                throw new TlvException("Invalid calendar authentication record type(" + Type + ").");
            }

            int publicationDataCount = 0;
            int signatureDataCount = 0;

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.PublicationData.TagType:
                        this[i] = PublicationData = new PublicationData(childTag);
                        publicationDataCount++;
                        break;
                    case Constants.SignatureData.TagType:
                        this[i] = SignatureData = new SignatureData(childTag);
                        signatureDataCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (publicationDataCount != 1)
            {
                throw new TlvException("Exactly one publication data must exist in calendar authentication record.");
            }

            if (signatureDataCount != 1)
            {
                throw new TlvException("Exactly one signature data must exist in calendar authentication record.");
            }
        }

        /// <summary>
        ///     Get publication data.
        /// </summary>
        public PublicationData PublicationData { get; }

        /// <summary>
        ///     Get signature data.
        /// </summary>
        public SignatureData SignatureData { get; }
    }
}