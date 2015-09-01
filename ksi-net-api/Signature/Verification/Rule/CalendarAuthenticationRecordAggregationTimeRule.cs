using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public class CalendarAuthenticationRecordAggregationTimeRule : IRule
    {
        public VerificationResult Verify(VerificationContext context)
        {
            if (context.CalendarAuthenticationRecord == null)
            {
                return VerificationResult.OK;
            }

            // TODO: Make context check for null?
            PublicationData calendarHashChainPublicationData = context.CalendarHashChain.PublicationData;
            PublicationData calendarAuthRecordPublicationData = context.CalendarAuthenticationRecord.PublicationData;
            if (calendarAuthRecordPublicationData.PublicationTime.Value != calendarHashChainPublicationData.PublicationTime.Value)
            {
                return VerificationResult.FAIL;
            }

            return VerificationResult.OK;
        }
    }
}