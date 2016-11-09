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

using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extend response PDU.
    /// </summary>
    public sealed class ExtendResponsePdu : KsiPdu
    {
        /// <summary>
        ///     Create extend response PDU from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public ExtendResponsePdu(ITlvTag tag) : base(tag)
        {
            CheckTagType(Constants.ExtendResponsePdu.TagType);

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.ExtendResponsePayload.TagType:
                        ExtendResponsePayload extendResponsePayload = new ExtendResponsePayload(childTag);
                        this[i] = extendResponsePayload;
                        Payloads.Add(extendResponsePayload);
                        break;
                    case Constants.ExtendErrorPayload.TagType:
                        ExtendErrorPayload extendErrorPayload = new ExtendErrorPayload(childTag);
                        this[i] = extendErrorPayload;
                        Payloads.Add(extendErrorPayload);
                        break;
                    case Constants.ExtenderConfigResponsePayload.TagType:
                        ExtenderConfigResponsePayload configResponsePayload = new ExtenderConfigResponsePayload(childTag);
                        this[i] = configResponsePayload;
                        Payloads.Add(configResponsePayload);
                        break;
                    case Constants.KsiPduHeader.TagType:
                    case Constants.KsiPdu.MacTagType:
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }
        }

        /// <summary>
        /// Get extend response payload
        /// </summary>
        /// <param name="requestId">Request ID</param>
        /// <returns></returns>
        public ExtendResponsePayload GetExtendResponsePayload(ulong requestId)
        {
            foreach (ExtendResponsePayload payload in GetPayloads<ExtendResponsePayload>())
            {
                if (payload.RequestId == requestId)
                {
                    return payload;
                }
            }

            return null;
        }

        /// <summary>
        /// Get extend error payload
        /// </summary>
        /// <returns></returns>
        public ExtendErrorPayload GetExtendErrorPayload()
        {
            return GetPayload<ExtendErrorPayload>();
        }

        /// <summary>
        /// Get aggregation configuration response payload
        /// </summary>
        /// <returns></returns>
        public ExtenderConfigResponsePayload GetExtenderConfigResponsePayload()
        {
            return GetPayload<ExtenderConfigResponsePayload>();
        }
    }
}