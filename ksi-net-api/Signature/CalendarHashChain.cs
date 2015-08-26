using System.Collections.Generic;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using System;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    /// Calendar hash chain TLV element
    /// </summary>
    public sealed class CalendarHashChain : CompositeTag
    {
        // TODO: Better name
        /// <summary>
        /// Calendar hash chain tag type
        /// </summary>
        public const uint TagType = 0x802;
        private const uint PublicationTimeTagType = 0x1;
        private const uint AggregationTimeTagType = 0x2;
        private const uint InputHashTagType = 0x5;

        private readonly IntegerTag _publicationTime;
        private readonly IntegerTag _aggregationTime;
        private readonly ImprintTag _inputHash;
        private readonly List<Link> _chain = new List<Link>();

        private readonly ulong _registrationTime;

        // TODO: Check if null
        /// <summary>
        /// Get aggregation time
        /// </summary>
        public ulong AggregationTime
        {
            get
            {
                // TODO: null or 0
                return _aggregationTime == null ? _publicationTime.Value : _aggregationTime.Value;
            }
        }

        public ulong RegistrationTime
        {
            get
            {
                return _registrationTime;
            }
        }

        public DataHash InputHash
        {
            get
            {
                return _inputHash.Value;
            }
        }

        /// <summary>
        /// Create new calendar hash chain TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public CalendarHashChain(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid calendar hash chain type: " + Type);
            }

            int publicationTimeCount = 0;
            int aggregationTimeCount = 0;
            int inputHashCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case PublicationTimeTagType:
                        _publicationTime = new IntegerTag(this[i]);
                        this[i] = _publicationTime;
                        publicationTimeCount++;
                        break;
                    case AggregationTimeTagType:
                        _aggregationTime = new IntegerTag(this[i]);
                        this[i] = _aggregationTime;
                        aggregationTimeCount++;
                        break;
                    case InputHashTagType:
                        _inputHash = new ImprintTag(this[i]);
                        this[i] = _inputHash;
                        inputHashCount++;
                        break;
                    case (uint)LinkDirection.Left:
                    case (uint)LinkDirection.Right:
                        Link chainTag = new Link(this[i]);
                        _chain.Add(chainTag);
                        this[i] = chainTag;
                        break;
                    default:
                        VerifyCriticalTag(this[i]);
                        break;
                }
            }

            if (publicationTimeCount != 1)
            {
                throw new InvalidTlvStructureException("Only one publication time must exist in calendar hash chain");
            }

            if (aggregationTimeCount > 1)
            {
                throw new InvalidTlvStructureException("Only one aggregation time is allowed in calendar hash chain");
            }

            if (inputHashCount != 1)
            {
                throw new InvalidTlvStructureException("Only one input hash must exist in calendar hash chain");
            }

            if (_chain.Count == 0)
            {
                throw new InvalidTlvStructureException("Links are missing in calendar hash chain");
            }

            _registrationTime = CalculateRegistrationTime();
        }

        private ulong CalculateRegistrationTime()
        {
            ulong r = _publicationTime.Value;
            ulong t = 0;
            // iterate over the chain in reverse
            
            for (int i = _chain.Count - 1; i >= 0; i--)
            {
                if (r <= 0)
                {
                    // TODO: Create child exception
                    throw new KsiException("Invalid calendar hash chain shape for publication time");
                }

                if (_chain[i].Direction == LinkDirection.Left)
                {
                    r = HighBit(r) - 1;
                } else
                {
                    t = t + HighBit(r);
                    r = r - HighBit(r);
                }
            }

            if (r != 0)
            {
                throw new KsiException("Calendar hash chain shape inconsistent with publication time");
            }

            return t;
        }

        static ulong HighBit(ulong n)
        {
            n |= (n >> 1);
            n |= (n >> 2);
            n |= (n >> 4);
            n |= (n >> 8);
            n |= (n >> 16);
            n |= (n >> 32);
            return n - (n >> 1);
        }

        /// <summary>
        /// Calendar hash chain link object which is imprint containing link direction
        /// </summary>
        private class Link : ImprintTag
        {
            private readonly LinkDirection _direction;

            public LinkDirection Direction
            {
                get
                {
                    return _direction;
                }
            }

            public Link(TlvTag tag) : base(tag)
            {
                if (tag.Type == (int) LinkDirection.Left)
                {
                    _direction = LinkDirection.Left;
                }

                if (tag.Type == (int) LinkDirection.Right)
                {
                    _direction = LinkDirection.Right;
                }

                if (_direction == 0)
                {
                    throw new InvalidTlvStructureException("Invalid calendar hash chain link type: " + Type);
                }
                
            }
            
        }


        
    }
}