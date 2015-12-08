using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule verifies that calendar authentication record aggregation time equals to calendar hash chain aggregation time.
    ///     Without calendar authentication record <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class CalendarAuthenticationRecordAggregationTimeRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        
        
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);
            CalendarAuthenticationRecord calendarAuthenticationRecord = signature.CalendarAuthenticationRecord;

            if (calendarAuthenticationRecord == null)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            CalendarHashChain calendarHashChain = GetCalendarHashChain(signature);

            return calendarHashChain.PublicationTime != calendarAuthenticationRecord.PublicationData.PublicationTime
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int06)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}