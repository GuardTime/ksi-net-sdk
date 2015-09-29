using System.Collections.ObjectModel;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature
{
    public class TestKsiSignature : IKsiSignature
    {
        public Rfc3161Record Rfc3161Record { get; set; }

        public bool IsRfc3161Signature
        {
            get { return Rfc3161Record != null; }
        }

        public CalendarHashChain CalendarHashChain { get; set; }
        public CalendarAuthenticationRecord CalendarAuthenticationRecord { get; set; }
        public PublicationRecord PublicationRecord { get; set; }
        public ulong AggregationTime { get; set; }


        public ReadOnlyCollection<AggregationHashChain> AggregationHashChains;
        public DataHash AggregationHashChainRootHash;
        public IKsiSignature ExtendedKsiSignature;

        public ReadOnlyCollection<AggregationHashChain> GetAggregationHashChains()
        {
            return AggregationHashChains;
        }

        public DataHash GetAggregationHashChainRootHash()
        {
            return AggregationHashChainRootHash;
        }

        public IKsiSignature Extend(CalendarHashChain calendarHashChain)
        {
            return ExtendedKsiSignature;
        }

        public IKsiSignature Extend(CalendarHashChain calendarHashChain, PublicationRecord publicationRecord)
        {
            return ExtendedKsiSignature;
        }
    }
}