using System;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class ExtendedSignatureAggregationChainRightLinksMatchesRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
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
            if (calendarHashChain == null)
            {
                throw new KsiVerificationException("Invalid calendar hash chain in signature: null");
            }

            CalendarHashChain extendedCalendarHashChain =
                context.GetExtendedTimeCalendarHashChain(calendarHashChain.PublicationData.PublicationTime);
            if (extendedCalendarHashChain == null)
            {
                throw new KsiVerificationException(
                    "Invalid extended calendar hash chain from context extension function: null");
            }

            return !calendarHashChain.AreRightLinksEqual(extendedCalendarHashChain)
                ? VerificationResult.Fail
                : VerificationResult.Ok;
        }
    }
}