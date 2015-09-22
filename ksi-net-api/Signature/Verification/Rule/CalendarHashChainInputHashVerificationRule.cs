using System;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Calendar hash chain input hash verification VerificationRule.
    /// </summary>
    public sealed class CalendarHashChainInputHashVerificationRule : VerificationRule
    {

        /// <see cref="VerificationRule.Verify"/>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (context.Signature == null)
            {
                // TODO: Better exception
                throw new InvalidOperationException("Signature cannot be null");
            }

            // If calendar hash chain is missing, verification successful
            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;
            if (calendarHashChain == null)
            {
                return VerificationResult.Ok;
            }

            DataHash aggregationHashChainRootHash = context.Signature.GetAggregationHashChainRootHash();
            if (aggregationHashChainRootHash == null)
            {
                return VerificationResult.Fail;
            }

            return aggregationHashChainRootHash != calendarHashChain.InputHash ? VerificationResult.Fail : VerificationResult.Ok;
        }
    }
}
