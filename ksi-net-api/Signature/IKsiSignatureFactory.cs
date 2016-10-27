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
using System.IO;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    /// KSI signature factory interface
    /// </summary>
    public interface IKsiSignatureFactory
    {
        /// <summary>
        ///     Get KSI signature instance from byte array.
        /// </summary>
        /// <param name="bytes">signature byte array</param>
        /// <param name="hash">Signed hash</param>
        /// <param name="level">Signed hash node level value in the aggregation tree</param>
        /// <returns>KSI signature</returns>
        IKsiSignature Create(byte[] bytes, DataHash hash = null, uint level = 0);

        /// <summary>
        ///     Get KSI signature instance from content byte array.
        /// </summary>
        /// <param name="contentBytes">signature content byte array</param>
        /// <param name="hash">Signed hash</param>
        /// <param name="level">Signed hash node level value in the aggregation tree</param>
        /// <returns>KSI signature</returns>
        IKsiSignature CreateByContent(byte[] contentBytes, DataHash hash = null, uint level = 0);

        /// <summary>
        ///     Get KSI signature instance from stream.
        /// </summary>
        /// <param name="stream">signature data stream</param>
        /// <param name="hash">Signed hash</param>
        /// <param name="level">Signed hash node level value in the aggregation tree</param>
        /// <returns>KSI signature</returns>
        IKsiSignature Create(Stream stream, DataHash hash = null, uint level = 0);

        /// <summary>
        ///     Get KSI signature instance from aggregation response payload.
        /// </summary>
        /// <param name="payload">aggregation response payload</param>
        /// <param name="hash">Signed hash</param>
        /// <param name="level">Signed hash node level value in the aggregation tree</param>
        /// <returns>KSI signature</returns>
        IKsiSignature Create(AggregationResponsePayload payload, DataHash hash, uint level = 0);

        /// <summary>
        ///     Get KSI signature instance from aggregation response payload.
        /// </summary>
        /// <param name="payload">legacy aggregation response payload</param>
        /// <param name="hash">Signed hash</param>
        /// <param name="level">Signed hash node level value in the aggregation tree</param>
        /// <returns>KSI signature</returns>
        IKsiSignature Create(LegacyAggregationResponsePayload payload, DataHash hash, uint level = 0);

        /// <summary>
        /// Get KSI signature instance from tlv tags
        /// </summary>
        /// <param name="aggregationHashChains">Aggregation hash chain tlv elements</param>
        /// <param name="calendarHashChain">Calendar hash chain tlv element</param>
        /// <param name="calendarAuthenticationRecord">Calendar authentication record tlv element</param>
        /// <param name="publicationRecord">Publication record tlv element</param>
        /// <param name="rfc3161Record">RFC3161 record tlv element</param>
        /// <param name="hash">Signed hash</param>
        /// <param name="level">Signed hash node level value in the aggregation tree</param>
        /// <returns></returns>
        IKsiSignature Create(ICollection<AggregationHashChain> aggregationHashChains, CalendarHashChain calendarHashChain,
                             CalendarAuthenticationRecord calendarAuthenticationRecord, PublicationRecordInSignature publicationRecord,
                             Rfc3161Record rfc3161Record, DataHash hash, uint level = 0);
    }
}