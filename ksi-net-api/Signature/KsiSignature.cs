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
        private DataHash _aggregationHashChainRootHash;

        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.KsiSignature.TagType;

        /// <summary>
        ///     Create new KSI signature TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public KsiSignature(ITlvTag tag) : base(tag)
        {
            SortAggregationHashChains();
        }

        /// <summary>
        /// Create new KSI signature TLV element.
        /// </summary>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="childTags">child TLV element list</param>
        public KsiSignature(bool nonCritical, bool forward, ITlvTag[] childTags)
            : base(Constants.KsiSignature.TagType, nonCritical, forward, childTags)
        {
            SortAggregationHashChains();
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.AggregationHashChain.TagType:
                    AggregationHashChain aggregationChainTag = childTag as AggregationHashChain ?? new AggregationHashChain(childTag);
                    _aggregationHashChains.Add(aggregationChainTag);
                    return aggregationChainTag;
                case Constants.CalendarHashChain.TagType:
                    return CalendarHashChain = childTag as CalendarHashChain ?? new CalendarHashChain(childTag);
                case Constants.PublicationRecord.TagTypeInSignature:
                    return PublicationRecord = childTag as PublicationRecordInSignature ?? new PublicationRecordInSignature(childTag);
                case Constants.AggregationAuthenticationRecord.TagType:
                    return AggregationAuthenticationRecord = childTag as AggregationAuthenticationRecord ?? new AggregationAuthenticationRecord(childTag);
                case Constants.CalendarAuthenticationRecord.TagType:
                    return CalendarAuthenticationRecord = childTag as CalendarAuthenticationRecord ?? new CalendarAuthenticationRecord(childTag);
                case Constants.Rfc3161Record.TagType:
                    return Rfc3161Record = childTag as Rfc3161Record ?? new Rfc3161Record(childTag);
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

            if (_aggregationHashChains.Count == 0)
            {
                throw new TlvException("Aggregation hash chains must exist in KSI signature.");
            }

            if (tagCounter[Constants.CalendarHashChain.TagType] > 1)
            {
                throw new TlvException("Only one calendar hash chain is allowed in KSI signature.");
            }

            if (tagCounter[Constants.CalendarHashChain.TagType] == 0 &&
                (tagCounter[Constants.PublicationRecord.TagTypeInSignature] != 0 || tagCounter[Constants.CalendarAuthenticationRecord.TagType] != 0))
            {
                throw new TlvException("No publication record or calendar authentication record is allowed in KSI signature if there is no calendar hash chain.");
            }

            if ((tagCounter[Constants.PublicationRecord.TagTypeInSignature] == 1 && tagCounter[Constants.CalendarAuthenticationRecord.TagType] == 1) ||
                tagCounter[Constants.PublicationRecord.TagTypeInSignature] > 1 ||
                tagCounter[Constants.CalendarAuthenticationRecord.TagType] > 1)
            {
                throw new TlvException("Only one from publication record or calendar authentication record is allowed in KSI signature.");
            }

            if (tagCounter[Constants.Rfc3161Record.TagType] > 1)
            {
                throw new TlvException("Only one RFC 3161 record is allowed in KSI signature.");
            }
        }

        /// <summary>
        /// Sorts aggregation hash chains.
        /// </summary>
        private void SortAggregationHashChains()
        {
            _aggregationHashChains.Sort(new AggregationHashChain.ChainIndexOrdering());
        }

        /// <summary>
        ///     Get aggregation authentication record if it exists.
        /// </summary>
        public AggregationAuthenticationRecord AggregationAuthenticationRecord { get; private set; }

        /// <summary>
        ///     Get RFC 3161 record
        /// </summary>
        public Rfc3161Record Rfc3161Record { get; private set; }

        /// <summary>
        ///     Is signature RFC 3161 format
        /// </summary>
        public bool IsRfc3161Signature => Rfc3161Record != null;

        /// <summary>
        ///     Get calendar hash chain.
        /// </summary>
        public CalendarHashChain CalendarHashChain { get; private set; }

        /// <summary>
        ///     Get calendar authentication record.
        /// </summary>
        public CalendarAuthenticationRecord CalendarAuthenticationRecord { get; private set; }

        /// <summary>
        ///     Get publication record.
        /// </summary>
        public PublicationRecordInSignature PublicationRecord { get; private set; }

        /// <summary>
        /// Get the identity of the signature.
        /// </summary>
        /// <returns></returns>
        [Obsolete("This property is obsolete. Use GetIdentity() method instead.", false)]
        public string Identity
        {
            get
            {
                if (_identity != null)
                {
                    return _identity;
                }

                _identity = "";

                foreach (IIdentity linkIdentity in GetIdentity())
                {
                    string id = linkIdentity.ClientId;
                    if (id.Length <= 0)
                    {
                        continue;
                    }

                    if (_identity.Length > 0)
                    {
                        _identity += " :: ";
                    }

                    _identity += id;
                }

                return _identity;
            }
        }

        /// <summary>
        /// Get the identity of the signature.
        /// </summary>
        /// <returns></returns>
        public IEnumerable<IIdentity> GetIdentity()
        {
            for (int i = _aggregationHashChains.Count - 1; i >= 0; i--)
            {
                AggregationHashChain chain = _aggregationHashChains[i];

                foreach (IIdentity identity in chain.GetIdentity())
                {
                    yield return identity;
                }
            }
        }

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
        ///     Get last aggregation hash chain output hash that is calculated from all aggregation hash chains
        /// </summary>
        /// <returns>output hash</returns>
        public DataHash GetLastAggregationHashChainRootHash()
        {
            if (_aggregationHashChainRootHash != null)
            {
                return _aggregationHashChainRootHash;
            }

            AggregationHashChainResult lastResult = new AggregationHashChainResult(0, _aggregationHashChains[0].InputHash);

            foreach (AggregationHashChain chain in _aggregationHashChains)
            {
                lastResult = chain.GetOutputHash(lastResult);
            }

            return _aggregationHashChainRootHash = lastResult.Hash;
        }

        /// <summary>
        ///     Get aggregation time.
        /// </summary>
        public ulong AggregationTime => _aggregationHashChains[0].AggregationTime;

        /// <summary>
        ///     Extend KSI signature with given calendar hash chain.
        /// </summary>
        /// <param name="calendarHashChain">calendar hash chain</param>
        /// <param name="signatureFactory">signature factory to be used when creating extended signature</param>
        /// <returns>extended KSI signature</returns>
        public IKsiSignature Extend(CalendarHashChain calendarHashChain, IKsiSignatureFactory signatureFactory = null)
        {
            return Extend(calendarHashChain, (PublicationRecordInSignature)null, signatureFactory);
        }

        /// <summary>
        ///     Extend signature to publication.
        /// </summary>
        /// <param name="calendarHashChain">extended calendar hash chain</param>
        /// <param name="publicationRecord">extended publication record</param>
        /// <param name="signatureFactory">signature factory to be used when creating extended signature</param>
        /// <returns>extended KSI signature</returns>
        public IKsiSignature Extend(CalendarHashChain calendarHashChain, PublicationRecordInPublicationFile publicationRecord, IKsiSignatureFactory signatureFactory = null)
        {
            return Extend(calendarHashChain, publicationRecord?.ConvertToPublicationRecordInSignature(), signatureFactory);
        }

        /// <summary>
        ///     Extend signature to publication.
        /// </summary>
        /// <param name="calendarHashChain">extended calendar hash chain</param>
        /// <param name="publicationRecord">extended publication record</param>
        /// <param name="signatureFactory">signature factory to be used when creating extended signature</param>
        /// <returns>extended KSI signature</returns>
        public IKsiSignature Extend(CalendarHashChain calendarHashChain, PublicationRecordInSignature publicationRecord, IKsiSignatureFactory signatureFactory = null)
        {
            Logger.Debug("Extending KSI signature.");

            if (calendarHashChain == null)
            {
                throw new KsiException("Invalid calendar hash chain: null.");
            }

            if (signatureFactory == null)
            {
                signatureFactory = new KsiSignatureFactory();
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
                    IKsiSignature signature = signatureFactory.CreateByContent(((MemoryStream)writer.BaseStream).ToArray(), GetAggregationHashChains()[0].InputHash);
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
    }
}