using System;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class ExtendedSignatureCalendarChainRootHashRule : VerificationRule
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

            if (context.Signature.PublicationRecord == null)
            {
                throw new KsiVerificationException("Invalid publications record in signature: null");
            }

            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;
            if (calendarHashChain == null)
            {
                throw new KsiVerificationException("Invalid calendar hash chain in signature: null");
            }

            CalendarHashChain extendedSignatureCalendarHashChain =
                context.GetExtendedTimeCalendarHashChain(calendarHashChain.PublicationTime);
            if (extendedSignatureCalendarHashChain == null)
            {
                throw new KsiVerificationException(
                    "Invalid extended calendar hash chain from context extension function: null");
            }

            return calendarHashChain.OutputHash != extendedSignatureCalendarHashChain.OutputHash
                ? VerificationResult.Fail
                : VerificationResult.Ok;
        }
    }
}