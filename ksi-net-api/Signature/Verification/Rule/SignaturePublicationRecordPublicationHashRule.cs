using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public class SignaturePublicationRecordPublicationHashRule : IRule
    {
        public VerificationResult Verify(VerificationContext context)
        {
            if (context.PublicationRecord == null)
            {
                return VerificationResult.OK;
            }

            // TODO: Check!
            PublicationData publicationRecordPublicationData = context.PublicationRecord.PublicationData;
            PublicationData calendarHashChainPublicationData = context.CalendarHashChain.PublicationData;

            if (publicationRecordPublicationData.PublicationTime.Value != calendarHashChainPublicationData.PublicationTime.Value)
            {
                return VerificationResult.FAIL;
            }
            return VerificationResult.OK;
        }
    }
}