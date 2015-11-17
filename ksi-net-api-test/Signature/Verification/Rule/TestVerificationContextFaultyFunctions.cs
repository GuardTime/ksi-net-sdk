using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public class TestVerificationContextFaultyFunctions : IVerificationContext
    {
        public DataHash DocumentHash { get; set; }
        public IKsiSignature Signature { get; set; }
        public PublicationData UserPublication { get; set; }
        public IKsiService KsiService { get; set; }
        public bool IsExtendingAllowed { get; set; }
        public IPublicationsFile PublicationsFile { get; set; }

        public CalendarHashChain GetExtendedLatestCalendarHashChain()
        {
            return GetExtendedTimeCalendarHashChain(null);
        }

        public CalendarHashChain GetExtendedTimeCalendarHashChain(ulong? publicationTime)
        {
            return null;
        }
    }
}