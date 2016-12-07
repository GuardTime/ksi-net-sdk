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
    ///     Certificate record TLV element.
    /// </summary>
    public sealed class CertificateRecord : CompositeTag
    {
        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.CertificateRecord.TagType;

        /// <summary>
        ///     Create new certificate record TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public CertificateRecord(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.CertificateRecord.CertificateIdTagType:
                    return CertificateId = GetRawTag(childTag);
                case Constants.CertificateRecord.X509CertificateTagType:
                    return X509Certificate = GetRawTag(childTag);
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

            if (tagCounter[Constants.CertificateRecord.CertificateIdTagType] != 1)
            {
                throw new TlvException("Exactly one certificate id must exist in certificate record.");
            }

            if (tagCounter[Constants.CertificateRecord.X509CertificateTagType] != 1)
            {
                throw new TlvException("Exactly one certificate must exist in certificate record.");
            }
        }

        /// <summary>
        ///     Get certificate ID.
        /// </summary>
        public RawTag CertificateId { get; private set; }

        /// <summary>
        ///     Get X509 certificate.
        /// </summary>
        public RawTag X509Certificate { get; private set; }
    }
}