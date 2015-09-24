using System;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public class TestVerificationContext : IVerificationContext
    {
        public TestVerificationContext()
        {
        }

        public DataHash DocumentHash { get; set; }
        public KsiSignature Signature { get; set; }
        public PublicationData UserPublication { get; set; }
        public IKsiService KsiService { get; set; }
        public bool IsExtendingAllowed { get; set; }
        public PublicationsFile PublicationsFile { get; set; }
        public CalendarHashChain GetExtendedLatestCalendarHashChain()
        {
            return GetExtendedTimeCalendarHashChain(null);
        }

        // TODO: Cache result and make signature mandatory and unchangeable
        public CalendarHashChain GetExtendedTimeCalendarHashChain(ulong? publicationTime)
        {
            if (KsiService == null)
            {
                throw new InvalidOperationException("Invalid KSI service: null");
            }

            return publicationTime == null ? KsiService.Extend(Signature.AggregationTime) : KsiService.Extend(Signature.AggregationTime, publicationTime.Value);
        }
    }
}