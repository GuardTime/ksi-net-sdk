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
using System.Collections.ObjectModel;
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using NLog;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     KSI Signature implementation.
    /// </summary>
    public sealed class KsiSignature : CompositeTag, IKsiSignature
    {
        private readonly List<AggregationHashChain> _aggregationHashChains = new List<AggregationHashChain>();
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private string _identity;

        /// <summary>
        ///     Create new KSI signature TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public KsiSignature(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.KsiSignature.TagType)
            {
                throw new TlvException("Invalid KSI signature type(" + Type + ").");
            }

            int calendarChainCount = 0;
            int publicationRecordCount = 0;
            int calendarAuthenticationRecordCount = 0;
            int rfc3161RecordCount = 0;

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.AggregationHashChain.TagType:
                        AggregationHashChain aggregationChainTag = new AggregationHashChain(childTag);
                        _aggregationHashChains.Add(aggregationChainTag);
                        this[i] = aggregationChainTag;
                        break;
                    case Constants.CalendarHashChain.TagType:
                        this[i] = CalendarHashChain = new CalendarHashChain(childTag);
                        calendarChainCount++;
                        break;
                    case Constants.PublicationRecord.TagTypeInSignature:
                        this[i] = PublicationRecord = new PublicationRecordInSignature(childTag);
                        publicationRecordCount++;
                        break;
                    case Constants.AggregationAuthenticationRecord.TagType:
                        this[i] = AggregationAuthenticationRecord = new AggregationAuthenticationRecord(childTag);
                        break;
                    case Constants.CalendarAuthenticationRecord.TagType:
                        this[i] = CalendarAuthenticationRecord = new CalendarAuthenticationRecord(childTag);
                        calendarAuthenticationRecordCount++;
                        break;
                    case Constants.Rfc3161Record.TagType:
                        this[i] = Rfc3161Record = new Rfc3161Record(childTag);
                        rfc3161RecordCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (_aggregationHashChains.Count == 0)
            {
                throw new TlvException("Aggregation hash chains must exist in KSI signature.");
            }

            if (calendarChainCount > 1)
            {
                throw new TlvException("Only one calendar hash chain is allowed in KSI signature.");
            }

            if (calendarChainCount == 0 && (publicationRecordCount != 0 || calendarAuthenticationRecordCount != 0))
            {
                throw new TlvException("No publication record or calendar authentication record is allowed in KSI signature if there is no calendar hash chain.");
            }

            if ((publicationRecordCount == 1 && calendarAuthenticationRecordCount == 1) ||
                publicationRecordCount > 1 ||
                calendarAuthenticationRecordCount > 1)
            {
                throw new TlvException("Only one from publication record or calendar authentication record is allowed in KSI signature.");
            }

            if (rfc3161RecordCount > 1)
            {
                throw new TlvException("Only one RFC 3161 record is allowed in KSI signature.");
            }

            _aggregationHashChains.Sort(new AggregationHashChain.ChainIndexOrdering());
        }

        /// <summary>
        ///     Get aggregation authentication record if it exists.
        /// </summary>
        public AggregationAuthenticationRecord AggregationAuthenticationRecord { get; }

        /// <summary>
        ///     Get RFC 3161 record
        /// </summary>
        public Rfc3161Record Rfc3161Record { get; }

        /// <summary>
        ///     Is signature RFC 3161 format
        /// </summary>
        public bool IsRfc3161Signature => Rfc3161Record != null;

        /// <summary>
        ///     Get calendar hash chain.
        /// </summary>
        public CalendarHashChain CalendarHashChain { get; }

        /// <summary>
        ///     Get calendar authentication record.
        /// </summary>
        public CalendarAuthenticationRecord CalendarAuthenticationRecord { get; }

        /// <summary>
        ///     Get publication record.
        /// </summary>
        public PublicationRecordInSignature PublicationRecord { get; }

        /// <summary>
        /// Get the identity of the signature.
        /// </summary>
        /// <returns></returns>
        public string Identity => _identity ?? (_identity = GetIdentity());

        /// <summary>
        /// Returns true if signature contains signature publication record element.
        /// </summary>
        /// <returns></returns>
        public bool IsExtended => PublicationRecord != null;

        /// <summary>
        ///     Get aggregation hash chains list.
        /// </summary>
        /// <returns>aggregations hash chains list</returns>
        public ReadOnlyCollection<AggregationHashChain> GetAggregationHashChains()
        {
            return _aggregationHashChains.AsReadOnly();
        }

        /// <summary>
        ///     Get aggregation hash chain output hash.
        /// </summary>
        /// <returns>output hash</returns>
        public DataHash GetAggregationHashChainRootHash()
        {
            // Store result
            AggregationHashChainResult lastResult = new AggregationHashChainResult(0, _aggregationHashChains[0].InputHash);

            foreach (AggregationHashChain chain in _aggregationHashChains)
            {
                lastResult = chain.GetOutputHash(lastResult);
            }

            return lastResult.Hash;
        }

        /// <summary>
        ///     Get aggregation time.
        /// </summary>
        public ulong AggregationTime => _aggregationHashChains[0].AggregationTime;

        /// <summary>
        ///     Extend KSI signature with given calendar hash chain.
        /// </summary>
        /// <param name="calendarHashChain">calendar hash chain</param>
        /// <returns>extended KSI signature</returns>
        public IKsiSignature Extend(CalendarHashChain calendarHashChain)
        {
            return Extend(calendarHashChain, (PublicationRecordInSignature)null);
        }

        /// <summary>
        ///     Extend signature to publication.
        /// </summary>
        /// <param name="calendarHashChain">extended calendar hash chain</param>
        /// <param name="publicationRecord">extended publication record</param>
        /// <returns>extended KSI signature</returns>
        public IKsiSignature Extend(CalendarHashChain calendarHashChain, PublicationRecordInPublicationFile publicationRecord)
        {
            return Extend(calendarHashChain, publicationRecord?.ConvertToPublicationRecordInSignature());
        }

        /// <summary>
        ///     Extend signature to publication.
        /// </summary>
        /// <param name="calendarHashChain">extended calendar hash chain</param>
        /// <param name="publicationRecord">extended publication record</param>
        /// <returns>extended KSI signature</returns>
        public IKsiSignature Extend(CalendarHashChain calendarHashChain, PublicationRecordInSignature publicationRecord)
        {
            Logger.Debug("Extending KSI signature.");

            if (calendarHashChain == null)
            {
                throw new KsiException("Invalid calendar hash chain: null.");
            }

            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                foreach (ITlvTag childTag in this)
                {
                    switch (childTag.Type)
                    {
                        case Constants.CalendarHashChain.TagType:
                            writer.WriteTag(calendarHashChain);
                            break;
                        case Constants.CalendarAuthenticationRecord.TagType:
                        case Constants.PublicationRecord.TagTypeInSignature:
                            break;
                        default:
                            writer.WriteTag(childTag);
                            break;
                    }
                }

                if (publicationRecord != null)
                {
                    writer.WriteTag(publicationRecord);
                }

                try
                {
                    KsiSignature signature = new KsiSignature(new RawTag(Constants.KsiSignature.TagType, false, false, ((MemoryStream)writer.BaseStream).ToArray()));
                    Logger.Debug("Extending KSI signature successful.");
                    return signature;
                }
                catch (TlvException e)
                {
                    Logger.Warn("Extending KSI signature failed: {0}", e);
                    throw;
                }
            }
        }

        private string GetIdentity()
        {
            string identity = "";

            foreach (AggregationHashChain chain in _aggregationHashChains)
            {
                string id = chain.GetChainIdentity();
                if (id.Length <= 0)
                {
                    continue;
                }
                if (identity.Length > 0)
                {
                    identity += ".";
                }
                identity += id;
            }
            return identity;
        }
    }
}