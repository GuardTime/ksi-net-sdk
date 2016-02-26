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
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publications file header TLV element.
    /// </summary>
    public sealed class PublicationsFileHeader : CompositeTag
    {
        private readonly IntegerTag _creationTime;
        private readonly StringTag _repositoryUri;
        private readonly IntegerTag _version;

        /// <summary>
        ///     Create publications file header TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public PublicationsFileHeader(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.PublicationsFileHeader.TagType)
            {
                throw new TlvException("Invalid certificate record type(" + Type + ").");
            }

            int versionCount = 0;
            int creationTimeCount = 0;
            int repositoryUriCount = 0;

            foreach (ITlvTag childTag in this)
            {
                switch (childTag.Type)
                {
                    case Constants.PublicationsFileHeader.VersionTagType:
                        _version = new IntegerTag(childTag);
                        versionCount++;
                        break;
                    case Constants.PublicationsFileHeader.CreationTimeTagType:
                        _creationTime = new IntegerTag(childTag.Type, childTag.NonCritical, childTag.Forward,
                            Util.DecodeUnsignedLong(childTag.EncodeValue(), 0, childTag.EncodeValue().Length));
                        creationTimeCount++;
                        break;
                    case Constants.PublicationsFileHeader.RepositoryUriTagType:
                        _repositoryUri = new StringTag(childTag);
                        repositoryUriCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (versionCount != 1)
            {
                throw new TlvException("Only one version must exist in publications file header.");
            }

            if (creationTimeCount != 1)
            {
                throw new TlvException("Only one creation time must exist in publications file header.");
            }

            if (repositoryUriCount > 1)
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