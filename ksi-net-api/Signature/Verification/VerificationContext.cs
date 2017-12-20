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

using System;
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
        private IDictionary<ulong, CalendarHashChain> _calendarHashChainCache;
        private long _latestCalendarGetTime;
        private readonly object _cacheLock = new object();

        /// <summary>
        ///     Create new verification context instance.
        /// </summary>
        public VerificationContext()
        {
        }

        /// <summary>
        ///     Create new verification context instance.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        public VerificationContext(IKsiSignature signature)
        {
            if (signature == null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            Signature = signature;
        }

        /// <summary>
        ///     Get or set document hash.
        /// </summary>
        public DataHash DocumentHash { get; set; }

        /// <summary>
        ///     Get or set document hash node level value in the aggregation tree
        /// </summary>
        public uint DocumentHashLevel { get; set; }

        /// <summary>
        ///     Get KSI signature.
        /// </summary>
        public IKsiSignature Signature { get; set; }

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
        ///     Get extended latest calendar hash chain.
        /// </summary>
        /// <returns>extended calendar hash chain</returns>
        public CalendarHashChain GetExtendedLatestCalendarHashChain()
        {
            return GetExtendedCalendarHashChain(null);
        }

        /// <summary>
        ///     Get extended calendar hash chain from given publication time.
        /// </summary>
        /// <param name="publicationTime">publication time</param>
        /// <returns>extended calendar hash chain</returns>
        public CalendarHashChain GetExtendedCalendarHashChain(ulong? publicationTime)
        {
            if (KsiService == null)
            {
                throw new KsiVerificationException("Invalid KSI service: null.");
            }

            if (Signature == null)
            {
                throw new KsiVerificationException("Invalid Signature: null.");
            }

            ulong cacheKey = publicationTime ?? 0;

            lock (_cacheLock)
            {
                if (_calendarHashChainCache == null)
                {
                    _calendarHashChainCache = new Dictionary<ulong, CalendarHashChain>();
                }
                else if (_calendarHashChainCache.ContainsKey(cacheKey))
                {
                    // when getting latest calendar hash chain and last extend is more than 1 sec ago then do not take from cache
                    // otherwise take from cache
                    if (publicationTime != null || _latestCalendarGetTime + 10000000 > DateTime.Now.Ticks)
                    {
                        return _calendarHashChainCache[cacheKey];
                    }

                    _calendarHashChainCache.Remove(cacheKey);
                }
            }

            CalendarHashChain calendarHashChain = publicationTime == null
                ? KsiService.Extend(Signature.AggregationTime)
                : KsiService.Extend(Signature.AggregationTime, publicationTime.Value);

            lock (_cacheLock)
            {
                _calendarHashChainCache[cacheKey] = calendarHashChain;

                if (publicationTime == null)
                {
                    _latestCalendarGetTime = DateTime.Now.Ticks;
                }
            }

            return calendarHashChain;
        }
    }
}