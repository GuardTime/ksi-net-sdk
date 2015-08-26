﻿using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using System;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    /// Aggregation hash chain TLV element
    /// </summary>
    public sealed class AggregationHashChain : CompositeTag
    {
        // TODO: Better name
        /// <summary>
        /// Aggregation hash chain tag type
        /// </summary>
        public const uint TagType = 0x801;
        private const uint AggregationTimeTagType = 0x2;
        private const uint ChainIndexTagType = 0x3;
        private const uint InputDataTagType = 0x4;
        private const uint InputHashTagType = 0x5;
        private const uint AggregationAlgorithmIdTagType = 0x6;
        
        private readonly IntegerTag _aggregationTime;
        private readonly List<IntegerTag> _chainIndex = new List<IntegerTag>();
        private readonly RawTag _inputData;
        private readonly ImprintTag _inputHash;
        private readonly IntegerTag _aggrAlgorithmId;
        private readonly List<Link> _chain = new List<Link>();

        /// <summary>
        /// Get hash chain input hash
        /// </summary>
        public DataHash InputHash
        {
            get
            {
                return _inputHash.Value;
            }
        }

        public ulong AggregationTime
        {
            get
            {
                return _aggregationTime.Value;
            }
        }

        /// <summary>
        /// Create new aggregation hash chain TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationHashChain(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid aggregation hash chain type: " + Type);
            }

            int aggregationTimeCount = 0;
            int inputDataCount = 0;
            int inputHashCount = 0;
            int aggrAlgorithmIdCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case AggregationTimeTagType:
                        _aggregationTime = new IntegerTag(this[i]);
                        this[i] = _aggregationTime;
                        aggregationTimeCount++;
                        break;
                    case ChainIndexTagType:
                        IntegerTag chainIndexTag = new IntegerTag(this[i]);
                        _chainIndex.Add(chainIndexTag);
                        this[i] = chainIndexTag;
                        break;
                    case InputDataTagType:
                        _inputData = new RawTag(this[i]);
                        this[i] = _inputData;
                        inputDataCount++;
                        break;
                    case InputHashTagType:
                        _inputHash = new ImprintTag(this[i]);
                        this[i] = _inputHash;
                        inputHashCount++;
                        break;
                    case AggregationAlgorithmIdTagType:
                        _aggrAlgorithmId = new IntegerTag(this[i]);
                        this[i] = _aggrAlgorithmId;
                        aggrAlgorithmIdCount++;
                        break;
                    case (uint)LinkDirection.Left:
                    case (uint)LinkDirection.Right:
                        Link linkTag = new Link(this[i], (LinkDirection)this[i].Type);
                        _chain.Add(linkTag);
                        this[i] = linkTag;
                        break;
                    default:
                        VerifyCriticalTag(this[i]);
                        break;
                }
            }

            if (aggregationTimeCount != 1)
            {
                throw new InvalidTlvStructureException("Only one aggregation time must exist in aggregation hash chain");
            }

            if (_chainIndex.Count == 0)
            {
                throw new InvalidTlvStructureException("Chain index is missing in aggregation hash chain");
            }

            if (inputDataCount > 1)
            {
                throw new InvalidTlvStructureException("Only one input data value is allowed in aggregation hash chain");
            }

            if (inputHashCount != 1)
            {
                throw new InvalidTlvStructureException("Only one input hash must exist in aggregation hash chain");
            }

            if (aggrAlgorithmIdCount != 1)
            {
                throw new InvalidTlvStructureException("Only one algorithm must exist in aggregation hash chain");
            }

            if (_chain.Count == 0)
            {
                throw new InvalidTlvStructureException("Links are missing in aggregation hash chain");
            }


        }

        /// <summary>
        /// Get output hash
        /// </summary>
        /// <param name="level">hash chain input level</param>
        /// <returns>output hash chain result</returns>
        public ChainResult GetOutputHash(ulong level)
        {
            // TODO: Check if not null
            DataHash lastHash = _inputHash.Value;
            for (int i = 0; i < _chain.Count; i++)
            {
                Link link = _chain[i];
                level += link.LevelCorrection + 1;

                if (link.Direction == LinkDirection.Left)
                {
                    lastHash = HashTogether(lastHash.Imprint, link.SiblingData, level);
                }
                if (link.Direction == LinkDirection.Right)
                {
                    lastHash = HashTogether(link.SiblingData, lastHash.Imprint, level);
                }
            }

            return new ChainResult(level, lastHash);
        }

         // TODO: Better name
        /// <summary>
        /// Hash two hashes together
        /// </summary>
        /// <param name="hashA">first hash</param>
        /// <param name="hashB">second hash</param>
        /// <param name="level">hash chain level</param>
        /// <returns>resulting hash</returns>
        private DataHash HashTogether(byte[] hashA, byte[] hashB, ulong level)
        {
            DataHasher hasher = new DataHasher(HashAlgorithm.GetById((byte)_aggrAlgorithmId.Value));
            hasher.AddData(hashA);
            hasher.AddData(hashB);
            hasher.AddData(Util.EncodeUnsignedLong(level));
            return hasher.GetHash();
        }

        private class Link : CompositeTag
        {
            // TODO: Better name
            private const uint LevelCorrectionTagType = 0x1;
            private const uint SiblingHashTagType = 0x2;
            private const uint MetaHashTagType = 0x3;

            private readonly IntegerTag _levelCorrection;
            private readonly ImprintTag _siblingHash;
            private readonly ImprintTag _metaHash;
            private readonly MetaData _metaData;

            private LinkDirection _direction;

            // the client ID extracted from metaHash
            private string _metaHashId;

            /// <summary>
            /// Get level correction
            /// </summary>
            public ulong LevelCorrection
            {
                get
                {
                    return _levelCorrection == null ? 0UL : _levelCorrection.Value;
                }
            }

            // TODO: Better name
            /// <summary>
            /// Get data byte array
            /// </summary>
            public byte[] SiblingData
            {
                get
                {
                    if (_siblingHash != null)
                    {
                        return _siblingHash.EncodeValue();
                    }

                    if (_metaHash != null)
                    {
                        return _metaHash.EncodeValue();
                    }

                    if (_metaData != null)
                    {
                        return _metaData.EncodeValue();
                    }

                    // TODO: Throw exception?
                    return null;
                }
            }

            /// <summary>
            ///  Get direction
            /// </summary>
            public LinkDirection Direction
            {
                get
                {
                    return _direction;
                }
            }


            public Link(TlvTag tag, LinkDirection direction) : base(tag)
            {
                int levelCorrectionCount = 0;
                int siblingHashCount = 0;
                int metaHashCount = 0;
                int metaDataCount = 0;

                for (int i = 0; i < Count; i++)
                {
                    switch (this[i].Type)
                    {
                        case LevelCorrectionTagType:
                            _levelCorrection = new IntegerTag(this[i]);
                            this[i] = _levelCorrection;
                            levelCorrectionCount++;
                            break;
                        case SiblingHashTagType:
                            _siblingHash = new ImprintTag(this[i]);
                            this[i] = _siblingHash;
                            siblingHashCount++;
                            break;
                        case MetaHashTagType:
                            _metaHash = new ImprintTag(this[i]);
                            this[i] = _metaHash;
                            metaHashCount++;
                            break;
                        case MetaData.TagType:
                            _metaData = new MetaData(this[i]);
                            this[i] = _metaData;
                            metaDataCount++;
                            break;
                        default:
                            VerifyCriticalTag(this[i]);
                            break;
                    }
                }

                if (levelCorrectionCount > 1)
                {
                    throw new InvalidTlvStructureException("Only one levelcorrection value is allowed in aggregation hash chain link");
                }

                if ((siblingHashCount > 1 || metaHashCount > 1 || metaDataCount > 1) || !(siblingHashCount == 1 ^ metaHashCount == 1 ^ metaDataCount == 1) || (siblingHashCount == 1 && metaHashCount == 1 && metaDataCount == 1))
                {
                    throw new InvalidTlvStructureException("Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link");
                }

                _direction = direction;
            }

        }

        private class MetaData : CompositeTag
        {
            // TODO: Better name
            public const uint TagType = 0x4;
            private const uint ClientIdTagType = 0x1;
            private const uint MachineIdTagType = 0x2;
            private const uint SequenceNumberTagType = 0x3;
            private const uint RequestTimeTagType = 0x4;

            private readonly StringTag _clientId;
            private readonly StringTag _machineId;
            private readonly IntegerTag _sequenceNr;

            // Please do keep in mind that request time is in milliseconds!
            private readonly IntegerTag _requestTime;

            public MetaData(TlvTag tag) : base(tag)
            {
                if (Type != TagType)
                {
                    throw new InvalidTlvStructureException("Invalid aggregation hash chain link metadata type: " + Type);
                }

                int clientIdCount = 0;
                int machineIdCount = 0;
                int sequenceNrCount = 0;
                int requestTimeCount = 0;

                for (int i = 0; i < Count; i++)
                {
                    switch (this[i].Type)
                    {
                        case ClientIdTagType:
                            _clientId = new StringTag(this[i]);
                            this[i] = _clientId;
                            clientIdCount++;
                            break;
                        case MachineIdTagType:
                            _machineId = new StringTag(this[i]);
                            this[i] = _machineId;
                            machineIdCount++;
                            break;
                        case SequenceNumberTagType:
                            _sequenceNr = new IntegerTag(this[i]);
                            this[i] = _sequenceNr;
                            sequenceNrCount++;
                            break;
                        case RequestTimeTagType:
                            _requestTime = new IntegerTag(this[i]);
                            this[i] = _requestTime;
                            requestTimeCount++;
                            break;
                        default:
                            VerifyCriticalTag(this[i]);
                            break;
                    }
                }

                if (clientIdCount != 1)
                {
                    throw new InvalidTlvStructureException("Only one client id must exist in aggregation hash chain link metadata");
                }

                if (machineIdCount > 1)
                {
                    throw new InvalidTlvStructureException("Only one machine id is allowed in aggregation hash chain link metadata");
                }

                if (sequenceNrCount > 1)
                {
                    throw new InvalidTlvStructureException("Only one sequence number is allowed in aggregation hash chain link metadata");
                }

                if (requestTimeCount > 1)
                {
                    throw new InvalidTlvStructureException("Only one request time is allowed in aggregation hash chain link metadata");
                }
            }
        }

        public class ChainIndexOrdering : IComparer<AggregationHashChain>
        {
            public int Compare(AggregationHashChain x, AggregationHashChain y)
            {
                int i = 0;
                for (i = 0; i < x._chainIndex.Count; i++)
                {
                    if (i >= y._chainIndex.Count)
                    {
                        return -1;
                    }

                    if (x._chainIndex[i].Value != y._chainIndex[i].Value)
                    {
                        // TODO: throw better exception
                        throw new KsiException("Chain index mismatch");
                    }
                }

                if (x._chainIndex.Count == y._chainIndex.Count)
                {
                    return 0;
                }

                return 1;
            }
        }

        /// <summary>
        /// Aggregation chain output result
        /// </summary>
        public class ChainResult
        {
            private readonly DataHash _hash;
            private readonly ulong _level;

            /// <summary>
            /// Get aggregation chain output hash
            /// </summary>
            public DataHash Hash
            {
                get
                {
                    return _hash;
                }
            }

            /// <summary>
            /// Get aggregation chain output hash level
            /// </summary>
            public ulong Level
            {
                get
                {
                    return _level;
                }
            }

            public ChainResult(ulong level, DataHash hash)
            {
                _level = level;
                _hash = hash;
            }

            public override string ToString()
            {
                return _hash + " " + _level;
            }
        }

    }
}