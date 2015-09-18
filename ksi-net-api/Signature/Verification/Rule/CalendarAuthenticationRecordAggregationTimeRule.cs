using System;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Calendar authentication record aggregation time verification rule.
    /// </summary>
    public sealed class CalendarAuthenticationRecordAggregationTimeRule : IRule
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

            CalendarAuthenticationRecord calendarAuthenticationRecord = context.CalendarAuthenticationRecord;
            if (calendarAuthenticationRecord == null)
            {
                throw new InvalidOperationException("Invalid calendar authentication record: null");
            }

            CalendarHashChain calendarHashChain = context.CalendarHashChain;
            if (calendarHashChain == null)
            {
                throw new InvalidOperationException("Invalid calendar hash chain: null");
            }

            if (calendarAuthenticationRecord.PublicationData.PublicationTime != calendarHashChain.PublicationData.PublicationTime)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}