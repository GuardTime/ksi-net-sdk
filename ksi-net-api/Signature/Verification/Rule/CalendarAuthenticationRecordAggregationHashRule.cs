using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule verifies that calendar authentication record publication hash equals to calendar hash chain publication hash.
    ///     Without calendar authentication record <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class CalendarAuthenticationRecordAggregationHashRule : VerificationRule
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

            return calendarHashChain.OutputHash != calendarAuthenticationRecord.PublicationData.PublicationHash
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int08)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}