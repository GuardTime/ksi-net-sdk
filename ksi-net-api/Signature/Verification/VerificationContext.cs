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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;

namespace Guardtime.KSI.Signature.Verification
{
    /// <summary>
    ///     Verification context.
    /// </summary>
    public class VerificationContext : IVerificationContext
    {
        readonly IDictionary<ulong, CalendarHashChain> _calendarHashChainCache = new Dictionary<ulong, CalendarHashChain>();

        /// <summary>
        ///     Create new verification context instance.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        public VerificationContext(IKsiSignature signature)
        {
            if (signature == null)
            {
                throw new KsiException("Invalid KSI signature: null.");
            }

            Signature = signature;
        }

        /// <summary>
        ///     Get or set document hash.
        /// </summary>
        public DataHash DocumentHash { get; set; }

        /// <summary>
        ///     Get KSI signature.
        /// </summary>
        public IKsiSignature Signature { get; }

        /// <summary>
        ///     Get or set user publication.
        /// </summary>
        public PublicationData UserPublication { get; set; }

        /// <summary>
        ///     Get or set KSI service.
        /// </summary>
        public IKsiService KsiService { get; set; }

        /// <summary>
        ///     Get or set if extending is allowed.
        /// </summary>
        public bool IsExtendingAllowed { get; set; }

        /// <summary>
        ///     Get or set publications file.
        /// </summary>
        public IPublicationsFile PublicationsFile { get; set; }

        /// <summary>
        /// Document hash node level value in the aggregation tree
        /// </summary>
        public uint Level { get; set; }

        /// <summary>
        ///     Get extended latest calendar hash chain.
        /// </summary>
        /// <returns>extended calendar hash chain</returns>
        public CalendarHashChain GetExtendedLatestCalendarHashChain()
        {
            return GetExtendedTimeCalendarHashChain(null);
        }

        /// <summary>
        ///     Get extended calendar hash chain from given publication time.
        /// </summary>
        /// <param name="publicationTime">publication time</param>
        /// <returns>extended calendar hash chain</returns>
        public CalendarHashChain GetExtendedTimeCalendarHashChain(ulong? publicationTime)
        {
            if (KsiService == null)
            {
                throw new KsiException("Invalid KSI service: null.");
            }

            if (Signature == null)
            {
                throw new KsiException("Invalid Signature: null.");
            }

            ulong cacheKey = publicationTime ?? 0;

            if (_calendarHashChainCache.ContainsKey(cacheKey))
            {
                return _calendarHashChainCache[cacheKey];
            }

            return _calendarHashChainCache[cacheKey] = publicationTime == null
                ? KsiService.Extend(Signature.AggregationTime)
                : KsiService.Extend(Signature.AggregationTime, publicationTime.Value);
        }
    }
}