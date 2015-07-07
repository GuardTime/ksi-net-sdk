using Guardtime.KSI.Publication;
using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    public class KsiSignatureDo : CompositeTag
    {
        public const uint TagType = 0x800;

        private readonly List<AggregationHashChain> _aggregationChains = new List<AggregationHashChain>();
        private readonly CalendarHashChain _calendarChain;
        private readonly PublicationRecord _publicationRecord;
        private readonly AggregationAuthenticationRecord _aggregationAuthenticationRecord;
        private readonly CalendarAuthenticationRecord _calendarAuthenticationRecord;
        private readonly Rfc3161Record _rfc3161Record;

        public ulong AggregationTime
        {
            get
            {
                return _calendarChain.AggregationTime;
            }
        }

        // Order aggregation chain list to correct order
        // TODO: Create interface for tags list
        public KsiSignatureDo(List<TlvTag> response) : base(0x800, false, false, response)
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
                    case PublicationRecord.TagType:
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
                    case PublicationRecord.TagType:
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
                    case PublicationRecord.TagType:
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
                throw new InvalidTlvStructureException("Signature data object must have one or more aggregation hash chains");
            }

            if (tags[1] != 1)
            {
                throw new InvalidTlvStructureException("Signature data object must contain one calendar hash chain");
            }

            if (!(tags[2] == 1 ^ tags[4] == 1))
            {
                throw new InvalidTlvStructureException("Only one of publication record ord calendar authentication record can be in signature data object");
            }

            // TODO: Aggregation hash chain if defined
        }
    }
}
