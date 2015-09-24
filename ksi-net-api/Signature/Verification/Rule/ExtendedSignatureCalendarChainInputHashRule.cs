using System;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class ExtendedSignatureCalendarChainInputHashRule : VerificationRule
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
                throw new KsiVerificationException("Invalid KSI signature in context: null");
            }

            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;
            CalendarHashChain extendedCalendarHashChain = calendarHashChain == null ? context.GetExtendedLatestCalendarHashChain() : context.GetExtendedTimeCalendarHashChain(calendarHashChain.PublicationTime);

            if (extendedCalendarHashChain == null)
            {
                throw new KsiVerificationException("Invalid extended calendar hash chain from context extension function: null");
            }

            if (context.Signature.GetAggregationHashChainRootHash() != extendedCalendarHashChain.InputHash)
            {
                // TODO: Log
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}