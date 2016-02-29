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

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publication record TLV element.
    /// </summary>
    public abstract class PublicationRecord : CompositeTag
    {
        /// <summary>
        ///     Create new publication record TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected PublicationRecord(ITlvTag tag) : base(tag)
        {
            int publicationDataCount = 0;

            foreach (ITlvTag childTag in this)
            {
                switch (childTag.Type)
                {
                    case Constants.PublicationData.TagType:
                        PublicationData = new PublicationData(childTag);
                        publicationDataCount++;
                        break;
                    case Constants.PublicationRecord.PublicationReferencesTagType:
                        StringTag refTag = new StringTag(childTag);
                        PublicationReferences.Add(refTag.Value);
                        break;
                    case Constants.PublicationRecord.PublicationRepositoryUriTagType:
                        StringTag uriTag = new StringTag(childTag);
                        RepositoryUri.Add(uriTag.Value);
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (publicationDataCount != 1)
            {
                throw new TlvException("Exactly one publication data must exist in publication record.");
            }
        }

        /// <summary>
        ///     Create new publication record TLV element from TLV element.
        /// </summary>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">child TLV element list</param>
        protected PublicationRecord(uint type, bool nonCritical, bool forward, ITlvTag[] value) : base(type, nonCritical, forward, value)
        {
        }

        /// <summary>
        ///     Get publication data.
        /// </summary>
        public PublicationData PublicationData { get; }

        /// <summary>
        ///     Get publication references.
        /// </summary>
        public IList<string> PublicationReferences { get; } = new List<string>();

        /// <summary>
        ///     Get publication repository uri.
        /// </summary>
        public IList<string> RepositoryUri { get; } = new List<string>();
    }
}