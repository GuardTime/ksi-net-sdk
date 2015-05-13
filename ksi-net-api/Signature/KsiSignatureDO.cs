using Guardtime.KSI.Publication;
using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    public class KsiSignatureDo : CompositeTag
    {
        protected List<AggregationHashChain> AggregationChains;

        private CalendarHashChain _calendarChain;

        private PublicationRecord _publicationRecord;

        private AggregationAuthenticationRecord _aggregationAuthenticationRecord;

        private CalendarAuthenticationRecord _calendarAuthenticationRecord;

        protected Rfc3161Record Rfc3161Record;

        public KsiSignatureDo(TlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x801:
                        if (AggregationChains == null)
                        {
                            AggregationChains = new List<AggregationHashChain>();
                        }

                        var aggregationChainTag = new AggregationHashChain(Value[i]);
                        AggregationChains.Add(aggregationChainTag);
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
                        Rfc3161Record = new Rfc3161Record(Value[i]);
                        Value[i] = Rfc3161Record;
                        break;
                }
            }
        }
    }
}
