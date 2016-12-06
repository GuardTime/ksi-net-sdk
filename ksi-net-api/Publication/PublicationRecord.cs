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
        }

        /// <summary>
        /// Validate the tag
        /// </summary>
        protected override void Validate()
        {
            base.Validate();

            int publicationDataCount = 0;

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.PublicationData.TagType:
                        this[i] = PublicationData = new PublicationData(childTag);
                        publicationDataCount++;
                        break;
                    case Constants.PublicationRecord.PublicationReferencesTagType:
                        StringTag refTag = new StringTag(childTag);
                        PublicationReferences.Add(refTag.Value);
                        this[i] = refTag;
                        break;
                    case Constants.PublicationRecord.PublicationRepositoryUriTagType:
                        StringTag uriTag = new StringTag(childTag);
                        RepositoryUri.Add(uriTag.Value);
                        this[i] = uriTag;
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
        ///     Get publication data.
        /// </summary>
        public PublicationData PublicationData { get; private set; }

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