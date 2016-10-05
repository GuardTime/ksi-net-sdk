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
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Utils;
using NLog;

namespace Guardtime.KSI.Signature.MultiSignature
{
    /// <summary>
    ///     Multi-signature implementation.
    /// </summary>
    public sealed class KsiMultiSignature
    {
        //     Multi-signature beginning bytes "MULTISIG".
        private static readonly byte[] FileBeginningMagicBytes = { 0x4d, 0x55, 0x4c, 0x54, 0x49, 0x53, 0x49, 0x47 };
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        private readonly KsiService _ksiService;
        private readonly KsiSignatureFactory _uniSignatureFactory;

        private readonly AggregationHashChainHolder _aggregationHashChains = new AggregationHashChainHolder();
        private readonly CalendarHashChainHolder _calendarHashChains = new CalendarHashChainHolder();
        private readonly PublicationRecordHolder _publicationRecords = new PublicationRecordHolder();
        private readonly CalendarAuthenticationRecordHolder _calendarAuthenticationRecords = new CalendarAuthenticationRecordHolder();
        private readonly Rfc3161RecordHolder _rfc3161Records = new Rfc3161RecordHolder();

        private readonly FirstAggregationHashChainsHolder _firstAggregationHashChains = new FirstAggregationHashChainsHolder();

        /// <summary>
        /// Create multi-signature instance
        /// </summary>
        /// <param name="ksiService">KSI serverice. Needed for extending signatures.</param>
        /// <param name="uniSignatureFactory">Factory for creating uni-signatures</param>
        public KsiMultiSignature(KsiSignatureFactory uniSignatureFactory, KsiService ksiService = null)
        {
            if (uniSignatureFactory == null)
            {
                throw new ArgumentNullException(nameof(uniSignatureFactory));
            }
            _uniSignatureFactory = uniSignatureFactory;
            _ksiService = ksiService;
        }

        /// <summary>
        /// Create multi-signature instance
        /// </summary>
        /// <param name="stream">Stream containing multi-signature content</param>
        /// <param name="ksiService">KSI serverice. Needed for extending signatures.</param>
        /// <param name="uniSignatureFactory">Factory for creating uni-signatures</param>
        public KsiMultiSignature(Stream stream, KsiSignatureFactory uniSignatureFactory, KsiService ksiService = null) : this(uniSignatureFactory, ksiService)
        {
            LoadSignatureContent(stream);
        }

        /// <summary>
        /// Load multi-signature content from stream.
        /// </summary>
        /// <param name="stream">Stream containing multi-signature content</param>
        private void LoadSignatureContent(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            VerifyMagicBytes(stream);

            using (TlvReader tlvReader = new TlvReader(stream))
            {
                while (tlvReader.BaseStream.Position < tlvReader.BaseStream.Length)
                {
                    ITlvTag tag = tlvReader.ReadTag();

                    switch (tag.Type)
                    {
                        case Constants.AggregationHashChain.TagType:
                            AggregationHashChain aggregationHashChain = new AggregationHashChain(tag);
                            _aggregationHashChains.Add(new AggregationHashChainKey(aggregationHashChain.AggregationTime, aggregationHashChain.GetChainIndex()),
                                aggregationHashChain);

                            break;
                        case Constants.CalendarHashChain.TagType:

                            CalendarHashChain calendarHashChain = new CalendarHashChain(tag);
                            _calendarHashChains.Add(calendarHashChain.AggregationTime, calendarHashChain);
                            break;
                        case Constants.PublicationRecord.TagTypeInSignature:
                            PublicationRecordInSignature publicationRecordInSignature = new PublicationRecordInSignature(tag);
                            _publicationRecords.Add(publicationRecordInSignature.PublicationData.PublicationTime, publicationRecordInSignature);
                            break;
                        case Constants.CalendarAuthenticationRecord.TagType:
                            CalendarAuthenticationRecord calendarAuthenticationRecord = new CalendarAuthenticationRecord(tag);
                            _calendarAuthenticationRecords.Add(calendarAuthenticationRecord.PublicationData.PublicationTime, calendarAuthenticationRecord);
                            break;
                        case Constants.Rfc3161Record.TagType:
                            Rfc3161Record rfc3161Record = new Rfc3161Record(tag);
                            _rfc3161Records.Add(rfc3161Record);
                            break;
                        default:
                            Logger.Info("Multi-signature container contains unknown element: {0} ", tag);

                            break;
                    }
                }

                FillFirstAggregationChainHolder();
            }
        }

        /// <summary>
        /// Get all tags held by the multi-signature
        /// </summary>
        /// <returns></returns>
        public ITlvTag[] GetAllTags()
        {
            List<ITlvTag> result = new List<ITlvTag>();

            foreach (AggregationHashChain value in _aggregationHashChains.Values)
            {
                result.Add(value);
            }

            foreach (CalendarHashChain value in _calendarHashChains.Values)
            {
                result.Add(value);
            }
            foreach (PublicationRecordInSignature value in _publicationRecords.Values)
            {
                result.Add(value);
            }
            foreach (CalendarAuthenticationRecord value in _calendarAuthenticationRecords.Values)
            {
                result.Add(value);
            }
            foreach (Rfc3161Record value in _rfc3161Records.GetAllValues())
            {
                result.Add(value);
            }

            return result.ToArray();
        }

        /// <summary>
        /// Get all used hash algorithms (used in first aggregation hash chains or in rfc3161 record).
        /// </summary>
        /// <returns></returns>
        public HashAlgorithm[] GetUsedHashAlgorithms()
        {
            List<HashAlgorithm> result = new List<HashAlgorithm>(GetHashAlgorithmsUsedInFirstAggregationHashChains());

            foreach (Rfc3161Record value in _rfc3161Records.GetAllValues())
            {
                DataHash dataHash = value.InputHash;

                if (!result.Contains(dataHash.Algorithm))
                {
                    result.Add(dataHash.Algorithm);
                }
            }

            return result.ToArray();
        }

        /// <summary>
        /// Get all hash algorithms that are used in first level aggregation hash chains
        /// </summary>
        /// <returns></returns>
        private List<HashAlgorithm> GetHashAlgorithmsUsedInFirstAggregationHashChains()
        {
            List<HashAlgorithm> result = new List<HashAlgorithm>();

            foreach (DataHash dataHash in _firstAggregationHashChains.Keys)
            {
                if (!result.Contains(dataHash.Algorithm))
                {
                    result.Add(dataHash.Algorithm);
                }
            }
            return result;
        }

        /// <summary>
        /// Fill first level aggregation chain holder
        /// </summary>
        private void FillFirstAggregationChainHolder()
        {
            foreach (AggregationHashChainKey key in _aggregationHashChains.Keys)
            {
                bool isFirst = true;
                ulong[] tmp = new ulong[key.ChainIndex.Length];

                foreach (AggregationHashChainKey key2 in _aggregationHashChains.Keys)
                {
                    if (key.AggregationTime != key2.AggregationTime)
                    {
                        continue;
                    }

                    if (key.ChainIndex.Length >= key2.ChainIndex.Length)
                    {
                        continue;
                    }

                    Array.Copy(key2.ChainIndex, tmp, tmp.Length);

                    // if exists chain index that contains current chain index then it is not the first level chain
                    if (Util.IsArrayEqual(key.ChainIndex, tmp))
                    {
                        isFirst = false;
                        break;
                    }
                }

                if (isFirst)
                {
                    AggregationHashChain aggregationHashChain = _aggregationHashChains[key];
                    _firstAggregationHashChains.Add(aggregationHashChain);
                }
            }
        }

        /// <summary>
        /// Verifies that given stream starts with proper bytes.
        /// </summary>
        /// <param name="stream"></param>
        public void VerifyMagicBytes(Stream stream)
        {
            byte[] magicBytes = new byte[FileBeginningMagicBytes.Length];
            stream.Read(magicBytes, 0, FileBeginningMagicBytes.Length);
            if (!Util.IsArrayEqual(magicBytes, FileBeginningMagicBytes))
            {
                throw new KsiMultiSignatureException("Invalid multi-signature magic bytes");
            }
        }

        /// <summary>
        /// Add uni-signature to multi-signature
        /// </summary>
        /// <param name="signature">Uni-signature to be added</param>
        public void Add(IKsiSignature signature)
        {
            if (signature == null)
            {
                throw new ArgumentNullException(nameof(signature), "Input signature can not be null");
            }

            AggregationHashChain firstAggregationHashChain = null;
            int maxIndexLength = 0;

            foreach (AggregationHashChain aggregationHashChain in signature.GetAggregationHashChains())
            {
                AggregationHashChainKey key = new AggregationHashChainKey(aggregationHashChain.AggregationTime, aggregationHashChain.GetChainIndex());

                if (_aggregationHashChains[key] != null)
                {
                    if (!_aggregationHashChains[key].Equals(aggregationHashChain))
                    {
                        throw new KsiException("Aggregation hash chain exists in multi-signature (searched by aggregation time and chain index), but the chain values do no match.");
                    }
                }
                else
                {
                    _aggregationHashChains.Add(key, aggregationHashChain);
                }

                if (maxIndexLength < key.ChainIndex.Length)
                {
                    maxIndexLength = key.ChainIndex.Length;
                    firstAggregationHashChain = aggregationHashChain;
                }
            }

            if (firstAggregationHashChain != null)
            {
                _firstAggregationHashChains.Add(firstAggregationHashChain);
            }

            CalendarHashChain existingCalendarHashChain = _calendarHashChains[signature.AggregationTime];

            if (existingCalendarHashChain != null && signature.CalendarHashChain != null && existingCalendarHashChain.PublicationTime < signature.CalendarHashChain.PublicationTime)
            {
                _publicationRecords.Remove(existingCalendarHashChain.PublicationTime);
                _calendarAuthenticationRecords.Remove(existingCalendarHashChain.PublicationTime);
                _calendarHashChains.Remove(signature.AggregationTime);
            }

            _calendarHashChains.Add(signature.CalendarHashChain);
            _publicationRecords.Add(signature.PublicationRecord);

            if (signature.CalendarAuthenticationRecord != null && !_publicationRecords.ContainsKey(signature.CalendarAuthenticationRecord.PublicationData.PublicationTime))
            {
                _calendarAuthenticationRecords.Add(signature.CalendarAuthenticationRecord.PublicationData.PublicationTime, signature.CalendarAuthenticationRecord);
            }

            if (signature.Rfc3161Record != null)
            {
                _rfc3161Records.Add(signature.Rfc3161Record);
            }
        }

        /// <summary>
        /// Add aggregation hash chain to multi-signature.
        /// </summary>
        /// <param name="aggregationHashChain">Aggregation hash chain to be added</param>
        public void Add(AggregationHashChain aggregationHashChain)
        {
            if (aggregationHashChain == null)
            {
                throw new ArgumentNullException(nameof(aggregationHashChain));
            }

            ulong[] chainIndex = aggregationHashChain.GetChainIndex();
            ulong[] parentChainIndex = new ulong[chainIndex.Length - 1];
            Array.Copy(chainIndex, parentChainIndex, parentChainIndex.Length);

            AggregationHashChainKey parentAggregationHashChainKey = new AggregationHashChainKey(aggregationHashChain.AggregationTime, parentChainIndex);
            AggregationHashChain parentAggregationHashChain = _aggregationHashChains[parentAggregationHashChainKey];

            if (parentAggregationHashChain == null)
            {
                throw new KsiMultiSignatureException("Cannot find parent aggregation chain. Make sure a parent aggregation hash chain is already added.");
            }

            _firstAggregationHashChains.Remove(parentAggregationHashChain.InputHash);

            AggregationHashChainResult hashChainResult = new AggregationHashChainResult(0, aggregationHashChain.InputHash);
            hashChainResult = aggregationHashChain.GetOutputHash(hashChainResult);

            if (parentAggregationHashChain.InputHash != hashChainResult.Hash)
            {
                throw new KsiMultiSignatureException("Aggregation hash chain output and parent chain input do not match.");
            }

            AggregationHashChainKey key = new AggregationHashChainKey(aggregationHashChain.AggregationTime, chainIndex);

            if (_aggregationHashChains[key] != null)
            {
                if (!_aggregationHashChains[key].Equals(aggregationHashChain))
                {
                    throw new KsiException(
                        "Aggregation hash chain to be added exists in multi-signature (searched by aggregation time and chain index), but the chain values do no match.");
                }
            }
            else
            {
                _aggregationHashChains.Add(key, aggregationHashChain);
                _firstAggregationHashChains.Add(aggregationHashChain);
            }
        }

        /// <summary>
        /// Get uni-signature from multi-signature
        /// </summary>
        /// <param name="documentHash">Hash of the document which signature is looked for</param>
        /// <returns></returns>
        public IKsiSignature Get(DataHash documentHash)
        {
            Logger.Info("Searching uni-signature for hash '{0}'", documentHash);

            if (documentHash == null)
            {
                throw new ArgumentNullException(nameof(documentHash));
            }

            DataHash dataHash = documentHash;
            Rfc3161Record rfc3161Record = _rfc3161Records[dataHash];
            AggregationHashChain aggregationHashChain = null;

            if (rfc3161Record != null)
            {
                DataHash rfc3161OutputHash = rfc3161Record.GetOutputHash(dataHash);

                foreach (HashAlgorithm algorithm in GetHashAlgorithmsUsedInFirstAggregationHashChains())
                {
                    IDataHasher hasher = KsiProvider.CreateDataHasher(algorithm);
                    hasher.AddData(rfc3161OutputHash.Imprint);

                    aggregationHashChain = _firstAggregationHashChains[hasher.GetHash()];

                    if (aggregationHashChain != null)
                    {
                        break;
                    }
                }
            }
            else
            {
                aggregationHashChain = _firstAggregationHashChains[dataHash];
            }

            if (aggregationHashChain == null)
            {
                throw new KsiMultiSignatureInvalidHashException("Cannot find such document hash: " + documentHash);
            }

            List<AggregationHashChain> chains = new List<AggregationHashChain>() { aggregationHashChain };

            AggregationHashChainKey key = new AggregationHashChainKey(aggregationHashChain.AggregationTime, aggregationHashChain.GetChainIndex());

            while (key.ChainIndex.Length > 1)
            {
                ulong[] newIndex = new ulong[key.ChainIndex.Length - 1];
                Array.Copy(key.ChainIndex, newIndex, newIndex.Length);
                key = new AggregationHashChainKey(key.AggregationTime, newIndex);
                aggregationHashChain = _aggregationHashChains[key];

                if (aggregationHashChain == null)
                {
                    throw new KsiException("Cannot find aggregation hash chain by aggregation hash chain key: " + key);
                }

                chains.Add(aggregationHashChain);
            }

            CalendarHashChain calendarHashChain = _calendarHashChains[aggregationHashChain.AggregationTime];
            PublicationRecordInSignature signaturePublicationRecord = null;
            CalendarAuthenticationRecord calendarAuthenticationRecord = null;

            if (calendarHashChain != null)
            {
                signaturePublicationRecord = _publicationRecords[calendarHashChain.PublicationTime];
                calendarAuthenticationRecord = _calendarAuthenticationRecords[calendarHashChain.PublicationTime];
            }

            IKsiSignature signature = _uniSignatureFactory.Create(chains, calendarHashChain, calendarAuthenticationRecord, signaturePublicationRecord, rfc3161Record, documentHash);
            return signature;
        }

        /// <summary>
        /// Remove uni-signature from multi-signature
        /// </summary>
        /// <param name="documentHash">>Hash of the document which signature will be deleted</param>
        public void Remove(DataHash documentHash)
        {
            IKsiSignature signature = Get(documentHash);

            List<AggregationHashChainKey> sameRoundAggregationHashChainKeys = GetSameRoundAggregationHashChainKeys(signature);
            RemoveAggregationHashChains(signature, sameRoundAggregationHashChainKeys);

            _firstAggregationHashChains.Remove(documentHash);

            if (signature.CalendarHashChain != null && sameRoundAggregationHashChainKeys.Count == 0)
            {
                _calendarHashChains.Remove(signature.CalendarHashChain.AggregationTime);

                if (signature.CalendarAuthenticationRecord != null)
                {
                    _calendarAuthenticationRecords.Remove(signature.CalendarAuthenticationRecord.PublicationData.PublicationTime);
                }

                if (signature.PublicationRecord != null)
                {
                    bool canDelete = true;

                    foreach (CalendarHashChain calendarHashChain in _calendarHashChains.Values)
                    {
                        if (calendarHashChain.PublicationTime == signature.PublicationRecord.PublicationData.PublicationTime)
                        {
                            canDelete = false;
                            break;
                        }
                    }

                    if (canDelete)
                    {
                        _publicationRecords.Remove(signature.PublicationRecord.PublicationData.PublicationTime);
                    }
                }
            }

            _rfc3161Records.Remove(documentHash);
        }

        /// <summary>
        /// Get keys of aggregation hash chains that were in the same aggregation round as the given signature. Returns only those chains that are different from the signature chains.
        /// </summary>
        /// <param name="signature"></param>
        /// <returns></returns>
        private List<AggregationHashChainKey> GetSameRoundAggregationHashChainKeys(IKsiSignature signature)
        {
            List<AggregationHashChainKey> signatureAggregationHashChainKeys = new List<AggregationHashChainKey>();

            foreach (AggregationHashChain aggregationHashChain in signature.GetAggregationHashChains())
            {
                signatureAggregationHashChainKeys.Add(new AggregationHashChainKey(aggregationHashChain.AggregationTime, aggregationHashChain.GetChainIndex()));
            }

            List<AggregationHashChainKey> sameRoundAggregationHashChainKeys = new List<AggregationHashChainKey>();

            foreach (AggregationHashChainKey key in _aggregationHashChains.Keys)
            {
                if (key.AggregationTime == signature.AggregationTime && !signatureAggregationHashChainKeys.Contains(key))
                {
                    sameRoundAggregationHashChainKeys.Add(key);
                }
            }
            return sameRoundAggregationHashChainKeys;
        }

        /// <summary>
        /// Remove given signature's aggregation hash chains from the holder. Do not remove the chains that are used by other signatures.
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="sameRoundChainKeys"></param>
        private void RemoveAggregationHashChains(IKsiSignature signature, List<AggregationHashChainKey> sameRoundChainKeys)
        {
            foreach (AggregationHashChain chain in signature.GetAggregationHashChains())
            {
                bool canDelete = true;

                ulong[] chainIndex = chain.GetChainIndex();

                foreach (AggregationHashChainKey existingChainKey in sameRoundChainKeys)
                {
                    if (existingChainKey.ChainIndex.Length <= chainIndex.Length)
                    {
                        continue;
                    }

                    if (Util.IsArrayEqual(chainIndex, existingChainKey.ChainIndex, 0, chainIndex.Length))
                    {
                        canDelete = false;
                        break;
                    }
                }

                if (canDelete)
                {
                    _aggregationHashChains.Remove(new AggregationHashChainKey(chain.AggregationTime, chainIndex));
                }
            }
        }

        /// <summary>
        /// Extends the uni-signatures to closest publication if there is a suitable publication.
        /// </summary>
        /// <param name="publicationsFile">Publications file</param>
        /// <param name="overwriteExtended">If true then re-extend already extended signatures.</param>
        public void Extend(IPublicationsFile publicationsFile, bool overwriteExtended = false)
        {
            if (_ksiService == null)
            {
                throw new KsiMultiSignatureException("KsiService is null. KsiService is needed for exending.");
            }

            Logger.Debug("Extending multi-signature.");

            ulong[] keys;

            if (overwriteExtended)
            {
                keys = new ulong[_publicationRecords.Count];
                _publicationRecords.Keys.CopyTo(keys, 0);

                foreach (ulong publicationTime in keys)
                {
                    if (publicationsFile.GetNearestPublicationRecord(publicationTime) != null)
                    {
                        _publicationRecords.Remove(publicationTime);
                    }
                }
            }

            keys = new ulong[_calendarHashChains.Count];
            _calendarHashChains.Keys.CopyTo(keys, 0);

            foreach (ulong aggregationTime in keys)
            {
                CalendarHashChain calendarHashChain = _calendarHashChains[aggregationTime];
                ulong currentPublicationTime = calendarHashChain.PublicationTime;

                if (!overwriteExtended && _publicationRecords[currentPublicationTime] != null)
                {
                    continue;
                }

                PublicationRecordInPublicationFile publicationRecord = publicationsFile.GetNearestPublicationRecord(aggregationTime);

                if (publicationRecord == null)
                {
                    continue;
                }

                ulong publicationTime = publicationRecord.PublicationData.PublicationTime;

                if (!_publicationRecords.ContainsKey(publicationTime))
                {
                    _publicationRecords.Add(publicationRecord.ConvertToPublicationRecordInSignature());
                }

                _calendarAuthenticationRecords.Remove(currentPublicationTime);

                if (currentPublicationTime != publicationTime)
                {
                    _calendarHashChains[aggregationTime] = _ksiService.Extend(aggregationTime, publicationTime);
                }
            }
        }

        /// <summary>
        /// Extends the uni-signatures to given publication record if the publication record is newer than uni-signature.
        /// </summary>
        /// <param name="publicationRecord">Publication record to extend to</param>
        /// <param name="overwriteExtended">If true then re-extend already extended signatures.</param>
        public void Extend(PublicationRecordInPublicationFile publicationRecord, bool overwriteExtended = false)
        {
            Extend(publicationRecord.ConvertToPublicationRecordInSignature(), overwriteExtended);
        }

        /// <summary>
        /// Extends the uni-signatures to given publication record if the publication record is newer than uni-signature.
        /// </summary>
        /// <param name="publicationRecord">Publication record to extend to</param>
        /// <param name="overwriteExtended">If true then re-extend already extended signatures.</param>
        public void Extend(PublicationRecordInSignature publicationRecord, bool overwriteExtended = false)
        {
            if (_ksiService == null)
            {
                throw new KsiMultiSignatureException("KsiService is null. KsiService is needed for exending.");
            }

            Logger.Debug("Extending multi-signature.");

            ulong publicationTime = publicationRecord.PublicationData.PublicationTime;
            _publicationRecords.Remove(publicationTime);

            bool addPublication = false;

            ulong[] keys = new ulong[_calendarHashChains.Count];
            _calendarHashChains.Keys.CopyTo(keys, 0);

            foreach (ulong aggregationTime in keys)
            {
                if (aggregationTime > publicationTime)
                {
                    continue;
                }

                CalendarHashChain calendarHashChain = _calendarHashChains[aggregationTime];

                if (!overwriteExtended && _publicationRecords[calendarHashChain.PublicationTime] != null)
                {
                    continue;
                }

                addPublication = true;

                _calendarAuthenticationRecords.Remove(calendarHashChain.PublicationTime);
                _publicationRecords.Remove(calendarHashChain.PublicationTime);

                if (calendarHashChain.PublicationTime != publicationTime)
                {
                    _calendarHashChains[aggregationTime] = _ksiService.Extend(aggregationTime, publicationTime);
                }
            }

            if (addPublication)
            {
                _publicationRecords.Add(publicationRecord);
            }
        }

        /// <summary>
        ///     Write KSI signature to stream.
        /// </summary>
        /// <param name="outputStream">output stream</param>
        public void WriteTo(Stream outputStream)
        {
            if (outputStream == null)
            {
                throw new KsiException("Invalid output stream: null.");
            }

            if (!outputStream.CanWrite)
            {
                throw new KsiException("Output stream is not writable.");
            }

            TlvWriter writer = new TlvWriter(outputStream);

            writer.Write(FileBeginningMagicBytes);

            WriteTags(_aggregationHashChains.Values, writer);
            WriteTags(_calendarHashChains.Values, writer);
            WriteTags(_calendarAuthenticationRecords.Values, writer);
            WriteTags(_publicationRecords.Values, writer);
            WriteTags(_rfc3161Records.GetAllValues(), writer);
        }

        private static void WriteTags<T>(IEnumerable<T> values, TlvWriter writer) where T : CompositeTag
        {
            foreach (T tag in values)
            {
                writer.WriteTag(tag);
            }
        }
    }
}