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
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            CalendarHashChain calendarHashChain = GetSignature(context).CalendarHashChain;

            // If calendar hash chain is missing, verification successful
            if (calendarHashChain == null)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            return calendarHashChain.AggregationTime != calendarHashChain.RegistrationTime
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int05)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}