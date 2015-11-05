using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule is used to verify calendar hash chain registration time (calculated from calendar hash chain shape) equality
    ///     to calendar hash chain aggregation time. If calendar hash chain is missing then status
    ///     <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class CalendarHashChainRegistrationTimeRule : VerificationRule
    {
        /// <summary>
        ///     Rule name.
        /// </summary>
        public const string RuleName = "CalendarHashChainRegistrationTimeRule";

        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new KsiException("Invalid verification context: null.");
            }

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null.");
            }

            // If calendar hash chain is missing, verification successful
            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;
            if (calendarHashChain == null)
            {
                return new VerificationResult(RuleName, VerificationResultCode.Ok);
            }

            return calendarHashChain.AggregationTime != calendarHashChain.RegistrationTime
                ? new VerificationResult(RuleName, VerificationResultCode.Fail, VerificationError.Int05)
                : new VerificationResult(RuleName, VerificationResultCode.Ok);
        }
    }
}