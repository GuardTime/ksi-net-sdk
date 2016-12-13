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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publications file header TLV element.
    /// </summary>
    public sealed class PublicationsFileHeader : CompositeTag
    {
        private IntegerTag _creationTime;
        private StringTag _repositoryUri;
        private IntegerTag _version;

        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.PublicationsFileHeader.TagType;

        /// <summary>
        ///     Create publications file header TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public PublicationsFileHeader(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.PublicationsFileHeader.VersionTagType:
                    return _version = GetIntegerTag(childTag);
                case Constants.PublicationsFileHeader.CreationTimeTagType:
                    return _creationTime = GetIntegerTag(childTag);
                case Constants.PublicationsFileHeader.RepositoryUriTagType:
                    return _repositoryUri = GetStringTag(childTag);
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

            if (tagCounter[Constants.PublicationsFileHeader.VersionTagType] != 1)
            {
                throw new TlvException("Exactly one version must exist in publications file header.");
            }

            if (tagCounter[Constants.PublicationsFileHeader.CreationTimeTagType] != 1)
            {
                throw new TlvException("Exactly one creation time must exist in publications file header.");
            }

            if (tagCounter[Constants.PublicationsFileHeader.RepositoryUriTagType] > 1)
            {
                throw new TlvException("Only one repository uri is allowed in publications file header.");
            }
        }

        /// <summary>
        ///     Get publications file creation time.
        /// </summary>
        public ulong CreationTime => _creationTime.Value;

        /// <summary>
        ///     Get publications file repository uri if it exists.
        /// </summary>
        public string RepositoryUri => _repositoryUri?.Value;

        /// <summary>
        ///     Get publications file version.
        /// </summary>
        public ulong Version => _version.Value;
    }
}