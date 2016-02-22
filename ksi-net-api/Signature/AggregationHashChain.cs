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
using NLog;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     Aggregation hash chain TLV element.
    /// </summary>
    public sealed class AggregationHashChain : CompositeTag
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
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

            foreach (ITlvTag childTag in this)
            {
                switch (childTag.Type)
                {
                    case Constants.AggregationHashChain.AggregationTimeTagType:
                        _aggregationTime = new IntegerTag(childTag);
                        aggregationTimeCount++;
                        break;
                    case Constants.AggregationHashChain.ChainIndexTagType:
                        IntegerTag chainIndexTag = new IntegerTag(childTag);
                        _chainIndex.Add(chainIndexTag);
                        break;
                    case Constants.AggregationHashChain.InputDataTagType:
                        _inputData = new RawTag(childTag);
                        inputDataCount++;
                        break;
                    case Constants.AggregationHashChain.InputHashTagType:
                        _inputHash = new ImprintTag(childTag);
                        inputHashCount++;
                        break;
                    case Constants.AggregationHashChain.AggregationAlgorithmIdTagType:
                        _aggrAlgorithmId = new IntegerTag(childTag);
                        aggrAlgorithmIdCount++;
                        break;
                    case (uint)LinkDirection.Left:
                    case (uint)LinkDirection.Right:
                        Link linkTag = new Link(childTag, (LinkDirection)childTag.Type);
                        _chain.Add(linkTag);
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (aggregationTimeCount != 1)
            {
                throw new TlvException("Only one aggregation time must exist in aggregation hash chain.");
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
                throw new TlvException("Only one input hash must exist in aggregation hash chain.");
            }

            if (aggrAlgorithmIdCount != 1)
            {
                throw new TlvException("Only one algorithm must exist in aggregation hash chain.");
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
            StringBuilder identity = new StringBuilder();
            foreach (Link aggregationChainLink in _chain)
            {
                string id = aggregationChainLink.GetIdentity();
                if (identity.Length > 0 && id.Length > 0)
                {
                    identity.Append(".");
                }
                identity.Append(id);
            }
            return identity.ToString();
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
            IDataHasher hasher = KsiProvider.GetDataHasher(HashAlgorithm.GetById((byte)_aggrAlgorithmId.Value));
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
            private readonly IntegerTag _levelCorrection;

            // the client ID extracted from metaHash
            private readonly MetaData _metaData;
            private readonly ImprintTag _metaHash;
            private readonly ImprintTag _siblingHash;

            public Link(ITlvTag tag, LinkDirection direction) : base(tag)
            {
                int levelCorrectionCount = 0;
                int siblingHashCount = 0;
                int metaHashCount = 0;
                int metaDataCount = 0;

                foreach (ITlvTag childTag in this)
                {
                    switch (childTag.Type)
                    {
                        case Constants.AggregationHashChain.Link.LevelCorrectionTagType:
                            _levelCorrection = new IntegerTag(childTag);
                            levelCorrectionCount++;
                            break;
                        case Constants.AggregationHashChain.Link.SiblingHashTagType:
                            _siblingHash = new ImprintTag(childTag);
                            siblingHashCount++;
                            break;
                        case Constants.AggregationHashChain.Link.MetaHashTagType:
                            _metaHash = new ImprintTag(childTag);
                            metaHashCount++;
                            break;
                        case Constants.AggregationHashChain.MetaData.TagType:
                            _metaData = new MetaData(childTag);
                            metaDataCount++;
                            break;
                        default:
                            VerifyUnknownTag(childTag);
                            break;
                    }
                }

                if (levelCorrectionCount > 1)
                {
                    throw new TlvException(
                        "Only one levelcorrection value is allowed in aggregation hash chain link.");
                }

                if (!Util.IsOneValueEqualTo(1, siblingHashCount, metaHashCount, metaDataCount))
                {
                    throw new TlvException(
                        "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link.");
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
                if (_metaHash != null)
                {
                    return CalculateIdentityFromMetaHash();
                }

                return _metaData != null ? _metaData.ClientId : "";
            }

            private string CalculateIdentityFromMetaHash()
            {
                byte[] bytes = _metaHash.Value.Imprint;

                if (bytes.Length < 3)
                {
                    Logger.Warn("Meta hash byte array too short. Length: {0}", bytes.Length);
                    return "";
                }

                int length = (bytes[1] << 8) + bytes[2];
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

                return _metaHash != null ? _metaHash.EncodeValue() : _metaData?.EncodeValue();
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

                foreach (ITlvTag childTag in this)
                {
                    switch (childTag.Type)
                    {
                        case Constants.AggregationHashChain.MetaData.ClientIdTagType:
                            _clientId = new StringTag(childTag);
                            clientIdCount++;
                            break;
                        case Constants.AggregationHashChain.MetaData.MachineIdTagType:
                            _machineId = new StringTag(childTag);
                            machineIdCount++;
                            break;
                        case Constants.AggregationHashChain.MetaData.SequenceNumberTagType:
                            _sequenceNumber = new IntegerTag(childTag);
                            sequenceNumberCount++;
                            break;
                        case Constants.AggregationHashChain.MetaData.RequestTimeTagType:
                            _requestTime = new IntegerTag(childTag);
                            requestTimeCount++;
                            break;
                        default:
                            VerifyUnknownTag(childTag);
                            break;
                    }
                }

                if (clientIdCount != 1)
                {
                    throw new TlvException(
                        "Only one client id must exist in aggregation hash chain link metadata.");
                }

                if (machineIdCount > 1)
                {
                    throw new TlvException(
                        "Only one machine id is allowed in aggregation hash chain link metadata.");
                }

                if (sequenceNumberCount > 1)
                {
                    throw new TlvException(
                        "Only one sequence number is allowed in aggregation hash chain link metadata.");
                }

                if (requestTimeCount > 1)
                {
                    throw new TlvException(
                        "Only one request time is allowed in aggregation hash chain link metadata.");
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