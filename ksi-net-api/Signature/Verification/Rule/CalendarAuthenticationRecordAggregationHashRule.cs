using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Calendar authentication record aggregation hash verification rule.
    /// </summary>
    public sealed class CalendarAuthenticationRecordAggregationHashRule : IRule
    {
        /// <summary>
        /// Verify given context with rule.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>verification result</returns>
        public override VerificationResult Verify(VerificationContext context)
        {
            if (context.CalendarAuthenticationRecord == null)
            {
                return VerificationResult.Ok;
            }

            // TODO: Make context check for null?
            PublicationData calendarAuthRecordPublicationData = context.CalendarAuthenticationRecord.PublicationData;
            PublicationData calendarHashChainPublicationData = context.CalendarHashChain.PublicationData;
            if (calendarAuthRecordPublicationData.PublicationHash.Value != calendarHashChainPublicationData.PublicationHash.Value)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}