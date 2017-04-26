/*
 * Copyright 2013-2017 Guardtime, Inc.
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

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     Signature data TLV element
    /// </summary>
    public sealed class SignatureData : CompositeTag
    {
        private RawTag _certificateId;
        private StringTag _certificateRepositoryUri;

        private StringTag _signatureType;
        private RawTag _signatureValue;

        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.SignatureData.TagType;

        /// <summary>
        ///     Create new signature data TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public SignatureData(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.SignatureData.SignatureTypeTagType:
                    return _signatureType = GetStringTag(childTag);
                case Constants.SignatureData.SignatureValueTagType:
                    return _signatureValue = GetRawTag(childTag);
                case Constants.SignatureData.CertificateIdTagType:
                    return _certificateId = GetRawTag(childTag);
                case Constants.SignatureData.CertificateRepositoryUriTagType:
                    return _certificateRepositoryUri = GetStringTag(childTag);
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

            if (tagCounter[Constants.SignatureData.SignatureTypeTagType] != 1)
            {
                throw new TlvException("Exactly one signature type must exist in signature data.");
            }

            if (tagCounter[Constants.SignatureData.SignatureValueTagType] != 1)
            {
                throw new TlvException("Exactly one signature value must exist in signature data.");
            }

            if (tagCounter[Constants.SignatureData.CertificateIdTagType] != 1)
            {
                throw new TlvException("Exactly one certificate id must exist in signature data.");
            }

            if (tagCounter[Constants.SignatureData.CertificateRepositoryUriTagType] > 1)
            {
                throw new TlvException("Only one certificate repository uri is allowed in signature data.");
            }
        }

        /// <summary>
        ///     Get certificate ID.
        /// </summary>
        public byte[] GetCertificateId()
        {
            return _certificateId.Value;
        }

        /// <summary>
        ///     Get signature value.
        /// </summary>
        public byte[] GetSignatureValue()
        {
            return _signatureValue.Value;
        }

        /// <summary>
        ///     Get signature type.
        /// </summary>
        public string SignatureType => _signatureType.Value;

        /// <summary>
        ///     Get certificate repository URI if it exists.
        /// </summary>
        public string CertificateRepositoryUri => _certificateRepositoryUri?.Value;
    }
}