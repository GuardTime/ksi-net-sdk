using System.Collections.ObjectModel;
using System.IO;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature
{
    public class TestKsiSignature : IKsiSignature
    {
        public Rfc3161Record Rfc3161Record { get; set; }

        public bool IsRfc3161Signature => Rfc3161Record != null;

        public CalendarHashChain CalendarHashChain { get; set; }
        public CalendarAuthenticationRecord CalendarAuthenticationRecord { get; set; }
        public PublicationRecordInSignature PublicationRecord { get; set; }
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

        public IKsiSignature Extend(CalendarHashChain calendarHashChain, PublicationRecordInPublicationFile publicationRecord)
        {
            return ExtendedKsiSignature;
        }

        public IKsiSignature Extend(CalendarHashChain calendarHashChain, PublicationRecordInSignature publicationRecord)
        {
            return ExtendedKsiSignature;
        }

        public void WriteTo(Stream outputStream)
        {
            using (TlvWriter writer = new TlvWriter(outputStream))
            {
                writer.WriteTag(this);
            }
        }

        public uint Type { get; set; }
        public bool NonCritical { get; set; }
        public bool Forward { get; set; }

        public byte[] EncodedValue;

        public byte[] EncodeValue()
        {
            return EncodedValue;
        }
    }
}