using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Calendar authentication record aggregation time verification rule.
    /// </summary>
    public class CalendarAuthenticationRecordAggregationTimeRule : IRule
    {
        /// <summary>
        /// Verify given context with rule.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>verification result</returns>
        public VerificationResult Verify(VerificationContext context)
        {
            if (context.CalendarAuthenticationRecord == null)
            {
                return VerificationResult.Ok;
            }

            // TODO: Make context check for null?
            PublicationData calendarHashChainPublicationData = context.CalendarHashChain.PublicationData;
            PublicationData calendarAuthRecordPublicationData = context.CalendarAuthenticationRecord.PublicationData;
            if (calendarAuthRecordPublicationData.PublicationTime.Value != calendarHashChainPublicationData.PublicationTime.Value)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}