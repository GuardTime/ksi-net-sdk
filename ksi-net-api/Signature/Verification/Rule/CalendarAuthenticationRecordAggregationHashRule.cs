using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule verifies that calendar authentication record publication hash equals to calendar hash chain publication hash.
    ///     Without calendar authentication record <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class CalendarAuthenticationRecordAggregationHashRule : VerificationRule
    {
        /// <summary>
        /// Rule name
        /// </summary>
        public const string RuleName = "CalendarAuthenticationRecordAggregationHashRule";

        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new KsiException("Invalid verification context: null.");
            }

            IKsiSignature signature = context.Signature;
            if (signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null.");
            }

            CalendarAuthenticationRecord calendarAuthenticationRecord = signature.CalendarAuthenticationRecord;
            if (calendarAuthenticationRecord == null)
            {
                return new VerificationResult(RuleName, VerificationResultCode.Ok);
            }

            CalendarHashChain calendarHashChain = signature.CalendarHashChain;
            if (calendarHashChain == null)
            {
                throw new KsiVerificationException("Calendar hash chain is missing from KSI signature.");
            }

            if (calendarHashChain.OutputHash != calendarAuthenticationRecord.PublicationData.PublicationHash)
            {
                return new VerificationResult(RuleName, VerificationResultCode.Fail, VerificationError.Int08);
            }

            return new VerificationResult(RuleName, VerificationResultCode.Ok);
        }
    }
}