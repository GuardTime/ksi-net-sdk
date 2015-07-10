using Guardtime.KSI.Publication;
using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    /// KSI Signature TLV element
    /// </summary>
    public class KsiSignatureDo : CompositeTag
    {
        // TODO: Better name
        /// <summary>
        /// KSI signature tag type
        /// </summary>
        public const uint TagType = 0x800;
        public const uint PublicationRecordTagType = 0x803;

        private readonly List<AggregationHashChain> _aggregationChains = new List<AggregationHashChain>();
        private readonly CalendarHashChain _calendarChain;
        private readonly PublicationRecord _publicationRecord;
        private readonly AggregationAuthenticationRecord _aggregationAuthenticationRecord;
        private readonly CalendarAuthenticationRecord _calendarAuthenticationRecord;
        private readonly Rfc3161Record _rfc3161Record;

        /// <summary>
        /// Get aggregation time
        /// </summary>
        public ulong AggregationTime
        {
            get
            {
                return _calendarChain.AggregationTime;
            }
        }

        // Order aggregation chain list to correct order
        // TODO: Create interface for tags list
        /// <summary>
        /// Create new KSI signature TLV element from TLV element
        /// </summary>
        /// <param name="tagList">TLV tag list</param>
        public KsiSignatureDo(List<TlvTag> tagList) : base(0x800, false, false, tagList)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case AggregationHashChain.TagType:
                        AggregationHashChain aggregationChainTag = new AggregationHashChain(this[i]);
                        _aggregationChains.Add(aggregationChainTag);
                        this[i] = aggregationChainTag;
                        break;
                    case CalendarHashChain.TagType:
                        _calendarChain = new CalendarHashChain(this[i]);
                        this[i] = _calendarChain;
                        break;
                    case PublicationRecordTagType:
                        _publicationRecord = new PublicationRecord(this[i]);
                        this[i] = _publicationRecord;
                        break;
                    case AggregationAuthenticationRecord.TagType:
                        _aggregationAuthenticationRecord = new AggregationAuthenticationRecord(this[i]);
                        this[i] = _aggregationAuthenticationRecord;
                        break;
                    case CalendarAuthenticationRecord.TagType:
                        _calendarAuthenticationRecord = new CalendarAuthenticationRecord(this[i]);
                        this[i] = _calendarAuthenticationRecord;
                        break;
                    case Rfc3161Record.TagType:
                        _rfc3161Record = new Rfc3161Record(this[i]);
                        this[i] = _rfc3161Record;
                        break;
                }
            }
        }

        /// <summary>
        /// Create new KSI signature TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public KsiSignatureDo(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case AggregationHashChain.TagType:
                        AggregationHashChain aggregationChainTag = new AggregationHashChain(this[i]);
                        _aggregationChains.Add(aggregationChainTag);
                        this[i] = aggregationChainTag;
                        break;
                    case CalendarHashChain.TagType:
                        _calendarChain = new CalendarHashChain(this[i]);
                        this[i] = _calendarChain;
                        break;
                    case PublicationRecordTagType:
                        _publicationRecord = new PublicationRecord(this[i]);
                        this[i] = _publicationRecord;
                        break;
                    case AggregationAuthenticationRecord.TagType:
                        _aggregationAuthenticationRecord = new AggregationAuthenticationRecord(this[i]);
                        this[i] = _aggregationAuthenticationRecord;
                        break;
                    case CalendarAuthenticationRecord.TagType:
                        _calendarAuthenticationRecord = new CalendarAuthenticationRecord(this[i]);
                        this[i] = _calendarAuthenticationRecord;
                        break;
                    case Rfc3161Record.TagType:
                        _rfc3161Record = new Rfc3161Record(this[i]);
                        this[i] = _rfc3161Record;
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
                throw new InvalidTlvStructureException("Invalid signature type: " + Type);
            }

            uint[] tags = new uint[6];

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case AggregationHashChain.TagType:
                        tags[0]++;
                        break;
                    case CalendarHashChain.TagType:
                        tags[1]++;
                        break;
                    case PublicationRecordTagType:
                        tags[2]++;
                        break;
                    case AggregationAuthenticationRecord.TagType:
                        tags[3]++;
                        break;
                    case CalendarAuthenticationRecord.TagType:
                        tags[4]++;
                        break;
                    case Rfc3161Record.TagType:
                        tags[5]++;
                        break;
                    default:
                        throw new InvalidTlvStructureException("Invalid tag", this[i]);
                }
            }

            if (tags[0] == 0)
            {
                throw new InvalidTlvStructureException("Aggregation hash chains must exist in signature data object");
            }

            if (tags[1] != 1)
            {
                throw new InvalidTlvStructureException("Only one calendar hash chain must exist in signature data object");
            }

            if ((tags[2] != 1 || tags[4] != 0) && (tags[2] != 0 || tags[4] != 1))
            {
                throw new InvalidTlvStructureException("Only one from publication record or calendar authentication record must exist in signature data object");
            }

            if (tags[5] > 1)
            {
                throw new InvalidTlvStructureException("Only one RFC 3161 record is allowed in signature data object");
            }

            // TODO: Aggregation hash chain if defined
        }
    }
}