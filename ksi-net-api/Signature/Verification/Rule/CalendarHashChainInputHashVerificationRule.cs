using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Calendar hash chain input hash verification rule.
    /// </summary>
    public sealed class CalendarHashChainInputHashVerificationRule : IRule
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

            DataHash aggregationHashChainRootHash = context.GetAggregationHashChainRootHash();
            if (aggregationHashChainRootHash == null)
            {
                return VerificationResult.Fail;
            }

            return aggregationHashChainRootHash != calendarHashChain.InputHash ? VerificationResult.Fail : VerificationResult.Ok;
        }
    }
}
