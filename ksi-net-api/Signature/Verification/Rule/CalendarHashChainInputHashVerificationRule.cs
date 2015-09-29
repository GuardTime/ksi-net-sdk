using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule verifies that last aggregation hash chain output hash is equal to calendar hash chain input hash. If calendar
    ///     hash chain is missing, status <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class CalendarHashChainInputHashVerificationRule : VerificationRule
    {
        /// <summary>
        /// Rule name.
        /// </summary>
        public const string RuleName = "CalendarHashChainInputHashVerificationRule";

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

            return context.Signature.GetAggregationHashChainRootHash() != calendarHashChain.InputHash
                ? new VerificationResult(RuleName, VerificationResultCode.Fail, VerificationError.Int03)
                : new VerificationResult(RuleName, VerificationResultCode.Ok);
        }
    }
}