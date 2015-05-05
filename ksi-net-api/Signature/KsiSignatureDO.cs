using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using System.Collections.Generic;

namespace Guardtime.KSI.Signature
{
    public class KsiSignatureDO : ICompositeTag
    {
        protected List<CompositeTag<AggregationHashChain>> aggregationChains;

        private CompositeTag<CalendarHashChain> calendarChain;

        private CompositeTag<PublicationRecord> publicationRecord;

        private CompositeTag<AggregationAuthenticationRecord> aggregationAuthenticationRecord;

        private CompositeTag<CalendarAuthenticationRecord> calendarAuthenticationRecord;

        protected CompositeTag<Rfc3161Record> rfc3161Record;

        public ITlvTag GetMember(ITlvTag tag)
        {
            switch (tag.Type)
            {
                case 0x801:
                    if (aggregationChains == null)
                    {
                        aggregationChains = new List<CompositeTag<AggregationHashChain>>();
                    }

                    var aggregationChainTag = new CompositeTag<AggregationHashChain>(tag, new AggregationHashChain());
                    aggregationChains.Add(aggregationChainTag);

                    return aggregationChainTag;
                case 0x802:
                    calendarChain = new CompositeTag<CalendarHashChain>(tag, new CalendarHashChain());
                    return calendarChain;
                case 0x803:
                    publicationRecord = new CompositeTag<PublicationRecord>(tag, new PublicationRecord());
                    return publicationRecord;
                case 0x804:
                    aggregationAuthenticationRecord = new CompositeTag<AggregationAuthenticationRecord>(tag, new AggregationAuthenticationRecord());
                    return aggregationAuthenticationRecord;
                case 0x805:
                    calendarAuthenticationRecord = new CompositeTag<CalendarAuthenticationRecord>(tag, new CalendarAuthenticationRecord());
                    return calendarAuthenticationRecord;
                case 0x806:
                    rfc3161Record = new CompositeTag<Rfc3161Record>(tag, new Rfc3161Record());
                    return rfc3161Record;
            }

            return null;
        }
    }
}
