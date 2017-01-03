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

using System;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extend PDU.
    /// </summary>
    [Obsolete]
    public sealed class LegacyExtendPdu : LegacyPdu
    {
        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.LegacyExtendPdu.TagType;

        /// <summary>
        ///     Create extend PDU from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        [Obsolete]
        public LegacyExtendPdu(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        ///     Create extend pdu from KSI header and extend pdu payload.
        /// </summary>
        /// <param name="header">KSI header</param>
        /// <param name="payload">Extend pdu payload</param>
        /// <param name="mac">Extend pdu mac</param>
        [Obsolete]
        public LegacyExtendPdu(PduHeader header, PduPayload payload, ImprintTag mac)
            : base(Constants.LegacyExtendPdu.TagType, false, false, new ITlvTag[] { header, payload, mac })
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.ExtendRequestPayload.LegacyTagType:
                    return Payload = childTag as LegacyExtendRequestPayload ?? new LegacyExtendRequestPayload(childTag);
                case Constants.ExtendResponsePayload.LegacyTagType:
                    return Payload = childTag as LegacyExtendResponsePayload ?? new LegacyExtendResponsePayload(childTag);
                case Constants.LegacyExtendErrorPayload.TagType:
                    return ErrorPayload = childTag as LegacyExtendErrorPayload ?? new LegacyExtendErrorPayload(childTag);
                default:
                    return base.ParseChild(childTag);
            }
        }
    }
}