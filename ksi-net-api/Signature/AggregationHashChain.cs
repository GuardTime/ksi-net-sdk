using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using System.Collections.Generic;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    /// Aggregation hash chain TLV element
    /// </summary>
    public class AggregationHashChain : CompositeTag
    {
        // TODO: Better name
        /// <summary>
        /// Aggregation authentication record tag type
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

        // the hash algorithm identified by aggrAlgorithmId
        // TODO: Protected?
        private HashAlgorithm AggrAlgorithm;

        /// <summary>
        /// Create new aggregation hash chain TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationHashChain(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case AggregationTimeTagType:
                        _aggregationTime = new IntegerTag(this[i]);
                        this[i] = _aggregationTime;
                        break;
                    case ChainIndexTagType:
                        IntegerTag chainIndexTag = new IntegerTag(this[i]);
                        _chainIndex.Add(chainIndexTag);
                        this[i] = chainIndexTag;
                        break;
                    case InputDataTagType:
                        _inputData = new RawTag(this[i]);
                        this[i] = _inputData;
                        break;
                    case InputHashTagType:
                        _inputHash = new ImprintTag(this[i]);
                        this[i] = _inputHash;
                        break;
                    case AggregationAlgorithmIdTagType:
                        _aggrAlgorithmId = new IntegerTag(this[i]);
                        this[i] = _aggrAlgorithmId;
                        break;
                    case (uint)LinkDirection.Left:
                    case (uint)LinkDirection.Right:
                        Link linkTag = new Link(this[i], (LinkDirection)this[i].Type);
                        _chain.Add(linkTag);
                        this[i] = linkTag;
                        break;
                }
            }
        }

        /// <summary>
        /// Check TLV structure.
        /// </summary>
        protected override void CheckStructure()
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid aggregation hash chain type: " + Type);
            }

            uint[] tags = new uint[7];

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case AggregationTimeTagType:
                        tags[0]++;
                        break;
                    case ChainIndexTagType:
                        tags[1]++;
                        break;
                    case InputDataTagType:
                        tags[2]++;
                        break;
                    case InputHashTagType:
                        tags[3]++;
                        break;
                    case AggregationAlgorithmIdTagType:
                        tags[4]++;
                        break;
                    case (uint)LinkDirection.Left:
                        tags[5]++;
                        break;
                    case (uint)LinkDirection.Right:
                        tags[6]++;
                        break;
                    default:
                        throw new InvalidTlvStructureException("Invalid tag", this[i]);
                }
            }

            if (tags[0] != 1)
            {
                throw new InvalidTlvStructureException("Only one aggregation time must exist in aggregation hash chain");
            }

            if (tags[1] == 0)
            {
                throw new InvalidTlvStructureException("Chain index is missing in aggregation hash chain");
            }

            if (tags[2] > 1)
            {
                throw new InvalidTlvStructureException("Only one input data value is allowed in aggregation hash chain");
            }

            if (tags[3] != 1)
            {
                throw new InvalidTlvStructureException("Only one input hash must exist in aggregation hash chain");
            }

            if (tags[4] != 1)
            {
                throw new InvalidTlvStructureException("Only one algorithm must exist in aggregation hash chain");
            }

            if ((tags[5] + tags[6]) == 0)
            {
                throw new InvalidTlvStructureException("Links are missing in aggregation hash chain");
            }
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


            public Link(TlvTag tag, LinkDirection direction) : base(tag)
            {
                for (int i = 0; i < Count; i++)
                {
                    switch (this[i].Type)
                    {
                        case LevelCorrectionTagType:
                            _levelCorrection = new IntegerTag(this[i]);
                            this[i] = _levelCorrection;
                            break;
                        case SiblingHashTagType:
                            _siblingHash = new ImprintTag(this[i]);
                            this[i] = _siblingHash;
                            break;
                        case MetaHashTagType:
                            _metaHash = new ImprintTag(this[i]);
                            this[i] = _metaHash;
                            break;
                        case MetaData.TagType:
                            _metaData = new MetaData(this[i]);
                            this[i] = _metaData;
                            break;
                    }
                }

                _direction = direction;
            }

            /// <summary>
            /// Check TLV structure.
            /// </summary>
            protected override void CheckStructure()
            {
                uint[] tags = new uint[4];

                for (int i = 0; i < Count; i++)
                {
                    switch (this[i].Type)
                    {
                        case LevelCorrectionTagType:
                            tags[0]++;
                            break;
                        case SiblingHashTagType:
                            tags[1]++;
                            break;
                        case MetaHashTagType:
                            tags[2]++;
                            break;
                        case MetaData.TagType:
                            tags[3]++;
                            break;
                        default:
                            throw new InvalidTlvStructureException("Invalid tag", this[i]);
                    }
                }

                if (tags[0] > 1)
                {
                    throw new InvalidTlvStructureException("Only one levelcorrection value is allowed in aggregation hash chain link");
                }

                if ((tags[1] == 1 && tags[2] == 1 && tags[3] == 1) || !(tags[1] == 1 ^ tags[2] == 1 ^ tags[3] == 1))
                {
                    throw new InvalidTlvStructureException("Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link");
                }
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
                for (int i = 0; i < Count; i++)
                {
                    switch (this[i].Type)
                    {
                        case ClientIdTagType:
                            _clientId = new StringTag(this[i]);
                            this[i] = _clientId;
                            break;
                        case MachineIdTagType:
                            _machineId = new StringTag(this[i]);
                            this[i] = _machineId;
                            break;
                        case SequenceNumberTagType:
                            _sequenceNr = new IntegerTag(this[i]);
                            this[i] = _sequenceNr;
                            break;
                        case RequestTimeTagType:
                            _requestTime = new IntegerTag(this[i]);
                            this[i] = _requestTime;
                            break;
                    }
                }
            }

            /// <summary>
            /// Check TLV structure.
            /// </summary>
            protected override void CheckStructure()
            {
                uint[] tags = new uint[4];

                for (int i = 0; i < Count; i++)
                {
                    switch (this[i].Type)
                    {
                        case ClientIdTagType:
                            tags[0]++;
                            break;
                        case MachineIdTagType:
                            tags[1]++;
                            break;
                        case SequenceNumberTagType:
                            tags[2]++;
                            break;
                        case RequestTimeTagType:
                            tags[3]++;
                            break;
                        default:
                            throw new InvalidTlvStructureException("Invalid tag", this[i]);
                    }
                }

                if (tags[0] != 1)
                {
                    throw new InvalidTlvStructureException("Only one client id must exist in aggregation hash chain link metadata");
                }

                if (tags[1] > 1)
                {
                    throw new InvalidTlvStructureException("Only one machine id is allowed in aggregation hash chain link metadata");
                }

                if (tags[2] > 1)
                {
                    throw new InvalidTlvStructureException("Only one sequence number is allowed in aggregation hash chain link metadata");
                }

                if (tags[3] > 1)
                {
                    throw new InvalidTlvStructureException("Only one request time is allowed in aggregation hash chain link metadata");
                }
            }
        } 
        
    }
}
