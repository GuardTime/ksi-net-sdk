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
        ///     Create new certificate record TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public CertificateRecord(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.CertificateRecord.TagType)
            {
                throw new TlvException("Invalid certificate record type(" + Type + ").");
            }

            int certificateIdCount = 0;
            int x509CertificateCount = 0;

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.CertificateRecord.CertificateIdTagType:
                        this[i] = CertificateId = new RawTag(childTag);
                        certificateIdCount++;
                        break;
                    case Constants.CertificateRecord.X509CertificateTagType:
                        this[i] = X509Certificate = new RawTag(childTag);
                        x509CertificateCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (certificateIdCount != 1)
            {
                throw new TlvException("Exactly one certificate id must exist in certificate record.");
            }

            if (x509CertificateCount != 1)
            {
                throw new TlvException("Exactly one certificate must exist in certificate record.");
            }
        }

        /// <summary>
        ///     Get certificate ID.
        /// </summary>
        public RawTag CertificateId { get; }

        /// <summary>
        ///     Get X509 certificate.
        /// </summary>
        public RawTag X509Certificate { get; }
    }
}