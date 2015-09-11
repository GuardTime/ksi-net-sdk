namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Calendar hash chain registration time verification rule.
    /// </summary>
    public sealed class CalendarHashChainRegistrationTimeRule : IRule
    {
        /// <summary>
        /// Verify given context with rule.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>verification result</returns>
        public override VerificationResult Verify(VerificationContext context)
        {

            // If calendar hash chain is missing, verification successful
            CalendarHashChain calendarHashChain = context.CalendarHashChain;
            if (calendarHashChain == null)
            {
                return VerificationResult.Ok;
            }

            return calendarHashChain.AggregationTime != calendarHashChain.RegistrationTime ? VerificationResult.Fail : VerificationResult.Ok;
        }
    }
}
