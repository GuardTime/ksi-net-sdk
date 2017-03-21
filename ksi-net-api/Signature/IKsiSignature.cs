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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     KSI signature interface.
    /// </summary>
    public interface IKsiSignature : ICompositeTag
    {
        /// <summary>
        ///     Get RFC 3161 record
        /// </summary>
        Rfc3161Record Rfc3161Record { get; }

        /// <summary>
        ///     Is signature RFC 3161 format
        /// </summary>
        bool IsRfc3161Signature { get; }

        /// <summary>
        ///     Get calendar hash chain.
        /// </summary>
        CalendarHashChain CalendarHashChain { get; }

        /// <summary>
        ///     Get calendar authentication record.
        /// </summary>
        CalendarAuthenticationRecord CalendarAuthenticationRecord { get; }

        /// <summary>
        ///     Get publication record.
        /// </summary>
        PublicationRecordInSignature PublicationRecord { get; }

        /// <summary>
        ///     Get aggregation time.
        /// </summary>
        ulong AggregationTime { get; }

        /// <summary>
        /// Get the identity of the signature.
        /// </summary>
        /// <returns></returns>
        [Obsolete("This property is obsolete. Use GetIdentity() method instead.", false)]
        string Identity { get; }

        /// <summary>
        /// Get the identity of the signature.
        /// </summary>
        /// <returns></returns>
        IEnumerable<IIdentity> GetIdentity();

        /// <summary>
        /// Returns true if signature contains signature publication record element.
        /// </summary>
        /// <returns></returns>
        bool IsExtended { get; }

        /// <summary>
        ///     Get aggregation hash chains list.
        /// </summary>
        /// <returns>aggregations hash chains list</returns>
        ReadOnlyCollection<AggregationHashChain> GetAggregationHashChains();

        /// <summary>
        ///     Get last aggregation hash chain output hash.
        /// </summary>
        /// <returns>output hash</returns>
        DataHash GetLastAggregationHashChainRootHash();

        /// <summary>
        ///     Extend KSI signature with given calendar hash chain.
        /// </summary>
        /// <param name="calendarHashChain">extended calendar hash chain</param>
        /// <param name="signatureFactory">signature factory to be used when creating extended signature</param>
        /// <returns>extended KSI signature</returns>
        IKsiSignature Extend(CalendarHashChain calendarHashChain, IKsiSignatureFactory signatureFactory = null);

        /// <summary>
        ///     Extend signature to publication.
        /// </summary>
        /// <param name="calendarHashChain">extended calendar hash chain</param>
        /// <param name="publicationRecord">extended publication record</param>
        /// <param name="signatureFactory">signature factory to be used when creating extended signature</param>
        /// <returns>extended KSI signature</returns>
        IKsiSignature Extend(CalendarHashChain calendarHashChain, PublicationRecordInPublicationFile publicationRecord, IKsiSignatureFactory signatureFactory = null);

        /// <summary>
        ///     Extend signature to publication.
        /// </summary>
        /// <param name="calendarHashChain">extended calendar hash chain</param>
        /// <param name="publicationRecord">extended publication record</param>
        /// <param name="signatureFactory">signature factory to be used when creating extended signature</param>
        /// <returns>extended KSI signature</returns>
        IKsiSignature Extend(CalendarHashChain calendarHashChain, PublicationRecordInSignature publicationRecord, IKsiSignatureFactory signatureFactory = null);

        /// <summary>
        ///     Write KSI signature to stream.
        /// </summary>
        /// <param name="outputStream">output stream</param>
        void WriteTo(Stream outputStream);
    }
}