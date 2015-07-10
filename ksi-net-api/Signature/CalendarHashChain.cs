using System.Collections.Generic;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    /// Calendar hash chain TLV element
    /// </summary>
    public class CalendarHashChain : CompositeTag
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

        /// <summary>
        /// Get aggregation time
        /// </summary>
        public ulong AggregationTime
        {
            get
            {
                return _aggregationTime.Value;
            }
        }

        /// <summary>
        /// Create new calendar hash chain TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public CalendarHashChain(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case PublicationTimeTagType:
                        _publicationTime = new IntegerTag(this[i]);
                        this[i] = _publicationTime;
                        break;
                    case AggregationTimeTagType:
                        _aggregationTime = new IntegerTag(this[i]);
                        this[i] = _aggregationTime;
                        break;
                    case InputHashTagType:
                        _inputHash = new ImprintTag(this[i]);
                        this[i] = _inputHash;
                        break;
                    case (uint)LinkDirection.Left:
                    case (uint)LinkDirection.Right:
                        Link chainTag = new Link(this[i]);
                        _chain.Add(chainTag);
                        this[i] = chainTag;
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
                throw new InvalidTlvStructureException("Invalid calendar hash chain type: " + Type);
            }

            uint[] tags = new uint[5];

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case PublicationTimeTagType:
                        tags[0]++;
                        break;
                    case AggregationTimeTagType:
                        tags[1]++;
                        break;
                    case InputHashTagType:
                        tags[2]++;
                        break;
                    case (uint)LinkDirection.Left:
                        tags[3]++;
                        break;
                    case (uint)LinkDirection.Right:
                        tags[4]++;
                        break;
                    default:
                        throw new InvalidTlvStructureException("Invalid tag", this[i]);
                }
            }

            if (tags[0] != 1)
            {
                throw new InvalidTlvStructureException("Only one publication time must exist in calendar hash chain");
            }

            if (tags[1] > 1)
            {
                throw new InvalidTlvStructureException("Only one aggregation time is allowed in calendar hash chain");
            }

            if (tags[2] != 1)
            {
                throw new InvalidTlvStructureException("Only one input hash must exist in calendar hash chain");
            }

            if ((tags[3] + tags[4]) == 0)
            {
                throw new InvalidTlvStructureException("Links are missing in calendar hash chain");
            }

            // TODO: Aggregation hash chain if defined
        }

        /// <summary>
        /// Calendar hash chain link object which is imprint containing link direction
        /// </summary>
        private class Link : ImprintTag
        {
            private readonly LinkDirection _direction;

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
                
            }
            
        }


        
    }
}