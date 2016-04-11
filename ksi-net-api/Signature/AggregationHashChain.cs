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
using System.Text;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     Aggregation hash chain TLV element.
    /// </summary>
    public sealed class AggregationHashChain : CompositeTag
    {
        private readonly IntegerTag _aggrAlgorithmId;
        private readonly IntegerTag _aggregationTime;
        private readonly List<Link> _chain = new List<Link>();
        private readonly List<IntegerTag> _chainIndex = new List<IntegerTag>();
        private readonly RawTag _inputData;
        private readonly ImprintTag _inputHash;

        /// <summary>
        ///     Create new aggregation hash chain TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationHashChain(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.AggregationHashChain.TagType)
            {
                throw new TlvException("Invalid aggregation hash chain type(" + Type + ").");
            }

            int aggregationTimeCount = 0;
            int inputDataCount = 0;
            int inputHashCount = 0;
            int aggrAlgorithmIdCount = 0;

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.AggregationHashChain.AggregationTimeTagType:
                        this[i] = _aggregationTime = new IntegerTag(childTag);
                        aggregationTimeCount++;
                        break;
                    case Constants.AggregationHashChain.ChainIndexTagType:
                        IntegerTag chainIndexTag = new IntegerTag(childTag);
                        _chainIndex.Add(chainIndexTag);
                        this[i] = chainIndexTag;
                        break;
                    case Constants.AggregationHashChain.InputDataTagType:
                        this[i] = _inputData = new RawTag(childTag);
                        inputDataCount++;
                        break;
                    case Constants.AggregationHashChain.InputHashTagType:
                        this[i] = _inputHash = new ImprintTag(childTag);
                        inputHashCount++;
                        break;
                    case Constants.AggregationHashChain.AggregationAlgorithmIdTagType:
                        this[i] = _aggrAlgorithmId = new IntegerTag(childTag);
                        aggrAlgorithmIdCount++;
                        break;
                    case (uint)LinkDirection.Left:
                    case (uint)LinkDirection.Right:
                        Link linkTag = new Link(childTag, (LinkDirection)childTag.Type);
                        _chain.Add(linkTag);
                        this[i] = linkTag;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (aggregationTimeCount != 1)
            {
                throw new TlvException("Exactly one aggregation time must exist in aggregation hash chain.");
            }

            if (_chainIndex.Count == 0)
            {
                throw new TlvException("Chain index is missing in aggregation hash chain.");
            }

            if (inputDataCount > 1)
            {
                throw new TlvException("Only one input data value is allowed in aggregation hash chain.");
            }

            if (inputHashCount != 1)
            {
                throw new TlvException("Exactly one input hash must exist in aggregation hash chain.");
            }

            if (aggrAlgorithmIdCount != 1)
            {
                throw new TlvException("Exactly one algorithm must exist in aggregation hash chain.");
            }

            if (_chain.Count == 0)
            {
                throw new TlvException("Links are missing in aggregation hash chain.");
            }
        }

        /// <summary>
        ///     Get hash chain input hash.
        /// </summary>
        public DataHash InputHash => _inputHash.Value;

        /// <summary>
        ///     Get aggregation time.
        /// </summary>
        public ulong AggregationTime => _aggregationTime.Value;

        /// <summary>
        ///     Get input data bytes if input data exists otherwise null.
        /// </summary>
        /// <returns>input data bytes</returns>
        public byte[] GetInputData()
        {
            return _inputData?.Value;
        }

        /// <summary>
        /// Get the (partial) signer identity from the current hash chain.
        /// </summary>
        /// <returns></returns>
        public string GetChainIdentity()
        {
            string identity = "";

            foreach (Link aggregationChainLink in _chain)
            {
                string id = aggregationChainLink.GetIdentity();
                if (id.Length <= 0)
                {
                    continue;
                }
                if (identity.Length > 0)
                {
                    identity = " :: " + identity;
                }
                identity = id + identity;
            }
            return identity;
        }

        /// <summary>
        ///     Get output hash.
        /// </summary>
        /// <param name="result">last hashing result</param>
        /// <returns>output hash chain result</returns>
        public AggregationHashChainResult GetOutputHash(AggregationHashChainResult result)
        {
            if (result == null)
            {
                throw new KsiException("Invalid aggregation chain result: null.");
            }

            DataHash lastHash = result.Hash;
            ulong level = result.Level;

            foreach (Link link in _chain)
            {
                level += link.LevelCorrection + 1;

                if (link.Direction == LinkDirection.Left)
                {
                    lastHash = GetStepHash(lastHash.Imprint, link.GetSiblingData(), level);
                }
                if (link.Direction == LinkDirection.Right)
                {
                    lastHash = GetStepHash(link.GetSiblingData(), lastHash.Imprint, level);
                }
            }

            return new AggregationHashChainResult(level, lastHash);
        }

        /// <summary>
        ///     Hash two hashes together.
        /// </summary>
        /// <param name="hashA">first hash</param>
        /// <param name="hashB">second hash</param>
        /// <param name="level">hash chain level</param>
        /// <returns>resulting hash</returns>
        private DataHash GetStepHash(byte[] hashA, byte[] hashB, ulong level)
        {
            IDataHasher hasher = KsiProvider.CreateDataHasher(HashAlgorithm.GetById((byte)_aggrAlgorithmId.Value));
            hasher.AddData(hashA);
            hasher.AddData(hashB);
            hasher.AddData(Util.EncodeUnsignedLong(level));
            return hasher.GetHash();
        }

        /// <summary>
        ///     Aggregation hash chain link.
        /// </summary>
        private class Link : CompositeTag
        {
            private const byte LegacyIdFirstOctet = 3;
            private readonly IntegerTag _levelCorrection;
            private readonly MetaData _metaData;
            private readonly ImprintTag _siblingHash;
            private readonly RawTag _legacyId;

            public Link(ITlvTag tag, LinkDirection direction) : base(tag)
            {
                int levelCorrectionCount = 0;
                int siblingHashCount = 0;
                int legacyIdCount = 0;
                int metaDataCount = 0;

                for (int i = 0; i < Count; i++)
                {
                    ITlvTag childTag = this[i];

                    switch (childTag.Type)
                    {
                        case Constants.AggregationHashChain.Link.LevelCorrectionTagType:
                            this[i] = _levelCorrection = new IntegerTag(childTag);
                            levelCorrectionCount++;
                            break;
                        case Constants.AggregationHashChain.Link.SiblingHashTagType:
                            this[i] = _siblingHash = new ImprintTag(childTag);
                            siblingHashCount++;
                            break;
                        case Constants.AggregationHashChain.Link.LegacyId:
                            this[i] = _legacyId = new RawTag(childTag);
                            legacyIdCount++;
                            break;
                        case Constants.AggregationHashChain.MetaData.TagType:
                            this[i] = _metaData = new MetaData(childTag);
                            metaDataCount++;
                            break;
                        default:
                            VerifyUnknownTag(childTag);
                            break;
                    }
                }

                if (levelCorrectionCount > 1)
                {
                    throw new TlvException("Only one levelcorrection value is allowed in aggregation hash chain link.");
                }

                if (!Util.IsOneValueEqualTo(1, siblingHashCount, legacyIdCount, metaDataCount))
                {
                    throw new TlvException("Exactly one of three from sibling hash, legacy id or metadata must exist in aggregation hash chain link.");
                }

                Direction = direction;
            }

            /// <summary>
            ///     Get level correction
            /// </summary>
            public ulong LevelCorrection => _levelCorrection?.Value ?? 0UL;

            /// <summary>
            ///     Get direction
            /// </summary>
            public LinkDirection Direction { get; }

            /// <summary>
            /// Get link identity
            /// </summary>
            /// <returns></returns>
            public string GetIdentity()
            {
                if (_legacyId != null)
                {
                    return GetLegacyIdString();
                }

                return _metaData != null ? _metaData.ClientId : "";
            }

            private string GetLegacyIdString()
            {
                byte[] bytes = _legacyId.Value;

                if (bytes[0] != LegacyIdFirstOctet)
                {
                    throw new TlvException("Invalid legacy id first octet: " + bytes[0]);
                }

                if (bytes.Length < 3)
                {
                    throw new TlvException("Legacy id byte array too short. Length: " + bytes.Length);
                }

                int length = bytes[2];

                if (bytes.Length < 3 + length)
                {
                    throw new TlvException("Invalid legacy id length value: " + length);
                }

                return Encoding.UTF8.GetString(bytes, 3, length);
            }

            /// <summary>
            ///     Get data byte array
            /// </summary>
            public byte[] GetSiblingData()
            {
                if (_siblingHash != null)
                {
                    return _siblingHash.EncodeValue();
                }

                return _legacyId != null ? _legacyId.EncodeValue() : _metaData?.EncodeValue();
            }
        }

        private class MetaData : CompositeTag
        {
            private readonly StringTag _clientId;
            private readonly StringTag _machineId;

            // Please do keep in mind that request time is in milliseconds!
            private readonly IntegerTag _requestTime;
            private readonly IntegerTag _sequenceNumber;

            public MetaData(ITlvTag tag) : base(tag)
            {
                if (Type != Constants.AggregationHashChain.MetaData.TagType)
                {
                    throw new TlvException("Invalid aggregation hash chain link metadata type(" + Type + ").");
                }

                int clientIdCount = 0;
                int machineIdCount = 0;
                int sequenceNumberCount = 0;
                int requestTimeCount = 0;

                for (int i = 0; i < Count; i++)
                {
                    ITlvTag childTag = this[i];

                    switch (childTag.Type)
                    {
                        case Constants.AggregationHashChain.MetaData.ClientIdTagType:
                            this[i] = _clientId = new StringTag(childTag);
                            clientIdCount++;
                            break;
                        case Constants.AggregationHashChain.MetaData.MachineIdTagType:
                            this[i] = _machineId = new StringTag(childTag);
                            machineIdCount++;
                            break;
                        case Constants.AggregationHashChain.MetaData.SequenceNumberTagType:
                            this[i] = _sequenceNumber = new IntegerTag(childTag);
                            sequenceNumberCount++;
                            break;
                        case Constants.AggregationHashChain.MetaData.RequestTimeTagType:
                            this[i] = _requestTime = new IntegerTag(childTag);
                            requestTimeCount++;
                            break;
                        default:
                            VerifyUnknownTag(childTag);
                            break;
                    }
                }

                if (clientIdCount != 1)
                {
                    throw new TlvException("Exactly one client id must exist in aggregation hash chain link metadata.");
                }

                if (machineIdCount > 1)
                {
                    throw new TlvException("Only one machine id is allowed in aggregation hash chain link metadata.");
                }

                if (sequenceNumberCount > 1)
                {
                    throw new TlvException("Only one sequence number is allowed in aggregation hash chain link metadata.");
                }

                if (requestTimeCount > 1)
                {
                    throw new TlvException("Only one request time is allowed in aggregation hash chain link metadata.");
                }
            }

            public string ClientId => _clientId.Value;
            public string MachineId => _machineId.Value;
            public ulong RequestTime => _requestTime.Value;
            public ulong SequenceNumber => _sequenceNumber.Value;
        }

        /// <summary>
        ///     Aggregation hash chain chain index ordering.
        /// </summary>
        internal class ChainIndexOrdering : IComparer<AggregationHashChain>
        {
            /// <summary>
            ///     Compare aggregation hash chains to eachother.
            /// </summary>
            /// <param name="x">aggregation hash chain</param>
            /// <param name="y">aggregation hash chain</param>
            /// <returns>0 if equal, 1 if bigger, -1 if smaller</returns>
            public int Compare(AggregationHashChain x, AggregationHashChain y)
            {
                for (int i = 0; i < x._chainIndex.Count; i++)
                {
                    if (i >= y._chainIndex.Count)
                    {
                        return -1;
                    }

                    if (x._chainIndex[i].Value != y._chainIndex[i].Value)
                    {
                        throw new KsiException("Chain index mismatch.");
                    }
                }

                return x._chainIndex.Count == y._chainIndex.Count ? 0 : 1;
            }
        }
    }
}