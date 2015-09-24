using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Signature.Verification.Rule
{

    public sealed class CalendarHashChainInputHashVerificationRule : VerificationRule
    {

        /// <see cref="VerificationRule.Verify"/>
        /// <exception cref="ArgumentNullException">thrown if context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature: null");
            }

            // If calendar hash chain is missing, verification successful
            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;
            if (calendarHashChain == null)
            {
                return VerificationResult.Ok;
            }

            return context.Signature.GetAggregationHashChainRootHash() != calendarHashChain.InputHash ? VerificationResult.Fail : VerificationResult.Ok;
        }
    }
}
