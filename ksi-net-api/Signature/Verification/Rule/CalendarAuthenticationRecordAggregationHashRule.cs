using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public class CalendarAuthenticationRecordAggregationHashRule : IRule
    {
        public VerificationResult Verify(VerificationContext context)
        {
            if (context.CalendarAuthenticationRecord == null)
            {
                return VerificationResult.OK;
            }

            // TODO: Make context check for null?
            PublicationData calendarAuthRecordPublicationData = context.CalendarAuthenticationRecord.PublicationData;
            PublicationData calendarHashChainPublicationData = context.CalendarHashChain.PublicationData;
            if (calendarAuthRecordPublicationData.PublicationHash.Value != calendarHashChainPublicationData.PublicationHash.Value)
            {
                return VerificationResult.FAIL;
            }

            return VerificationResult.OK;
        }
    }
}