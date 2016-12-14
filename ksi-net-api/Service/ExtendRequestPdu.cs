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

using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extend request PDU.
    /// </summary>
    public sealed class ExtendRequestPdu : Pdu
    {
        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.ExtendRequestPdu.TagType;

        /// <summary>
        ///     Create extend request PDU from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public ExtendRequestPdu(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.ExtendRequestPayload.TagType:
                    ExtendRequestPayload extendRequestPayload = childTag as ExtendRequestPayload ?? new ExtendRequestPayload(childTag);
                    Payloads.Add(extendRequestPayload);
                    return extendRequestPayload;
                case Constants.ExtenderConfigRequestPayload.TagType:
                    ExtenderConfigRequestPayload configRequestPayload = childTag as ExtenderConfigRequestPayload ?? new ExtenderConfigRequestPayload(childTag);
                    Payloads.Add(configRequestPayload);
                    return configRequestPayload;
                default:
                    return base.ParseChild(childTag);
            }
        }

        /// <summary>
        ///     Create extend request pdu from KSI header and extend pdu payload.
        /// </summary>
        /// <param name="header">KSI header</param>
        /// <param name="payload">Extend pdu payload</param>
        /// <param name="hmacAlgorithm">HMAC algorithm</param>
        /// <param name="key">hmac key</param>
        public ExtendRequestPdu(PduHeader header, PduPayload payload, HashAlgorithm hmacAlgorithm, byte[] key)
            : base(Constants.ExtendRequestPdu.TagType, header, payload, hmacAlgorithm, key)
        {
        }
    }
}