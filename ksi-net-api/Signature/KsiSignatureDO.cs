using Guardtime.KSI.Publication;
using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    public class KsiSignatureDo : CompositeTag
    {
        private List<AggregationHashChain> _aggregationChains;
        private CalendarHashChain _calendarChain;
        private PublicationRecord _publicationRecord;
        private AggregationAuthenticationRecord _aggregationAuthenticationRecord;
        private CalendarAuthenticationRecord _calendarAuthenticationRecord;
        private Rfc3161Record _rfc3161Record;

        // TODO: Create interface for tags list
        public KsiSignatureDo(List<TlvTag> response) : base(0x800, false, false, response)
        {
            BuildStructure();
        }


        public KsiSignatureDo(TlvTag tag) : base(tag)
        {
            BuildStructure();
        }

        private void BuildStructure()
        {
            for (int i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x801:
                        if (_aggregationChains == null)
                        {
                            _aggregationChains = new List<AggregationHashChain>();
                        }

                        AggregationHashChain aggregationChainTag = new AggregationHashChain(Value[i]);
                        _aggregationChains.Add(aggregationChainTag);
                        Value[i] = aggregationChainTag;
                        break;
                    case 0x802:
                        _calendarChain = new CalendarHashChain(Value[i]);
                        Value[i] = _calendarChain;
                        break;
                    case 0x803:
                        _publicationRecord = new PublicationRecord(Value[i]);
                        Value[i] = _publicationRecord;
                        break;
                    case 0x804:
                        _aggregationAuthenticationRecord = new AggregationAuthenticationRecord(Value[i]);
                        Value[i] = _aggregationAuthenticationRecord;
                        break;
                    case 0x805:
                        _calendarAuthenticationRecord = new CalendarAuthenticationRecord(Value[i]);
                        Value[i] = _calendarAuthenticationRecord;
                        break;
                    case 0x806:
                        _rfc3161Record = new Rfc3161Record(Value[i]);
                        Value[i] = _rfc3161Record;
                        break;
                }
            }
        }

        protected override void CheckStructure()
        {
            Dictionary<uint, int> tagCount = new Dictionary<uint, int>(); 
            for (int i = 0; i < Value.Count; i++)
            {
                tagCount[Value[i].Type] = tagCount.ContainsKey(Value[i].Type) ? tagCount[Value[i].Type] + 1 : 1;

                switch (Value[i].Type)
                {
                    case 0x801:
                    case 0x802:
                    case 0x803:
                    case 0x804:
                    case 0x805:
                    case 0x806:
                        break;
                    default:
                        throw new InvalidTlvStructureException("Invalid tag", Value[i]);
                }
            }

            if (!tagCount.ContainsKey(0x801) || tagCount[0x801] == 0)
            {
                throw new InvalidTlvStructureException("Signature data object must have one or more aggregation hash chains");
            }

            if (!tagCount.ContainsKey(0x802))
            {
                throw new InvalidTlvStructureException("Signature data object must contain calendar hash chain");
            }

            if (!(tagCount.ContainsKey(0x803) ^ tagCount.ContainsKey(0x805)))
            {
                throw new InvalidTlvStructureException("Signature data object must contain publication record or calendar authentication record");
            }

            // TODO: Aggregation hash chain if defined
        }
    }
}
