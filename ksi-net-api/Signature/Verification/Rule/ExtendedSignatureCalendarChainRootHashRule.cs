using System;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class ExtendedSignatureCalendarChainRootHashRule : VerificationRule
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

            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;
            if (calendarHashChain == null)
            {
                throw new InvalidOperationException("Invalid calendar hash chain: null");
            }

            CalendarHashChain extendedSignatureCalendarHashChain = context.GetExtendedTimeCalendarHashChain(calendarHashChain.PublicationData.PublicationTime);
            if (extendedSignatureCalendarHashChain == null)
            {
                throw new InvalidOperationException("Invalid extended calendar hash chain: null");
            }

            return calendarHashChain.OutputHash != extendedSignatureCalendarHashChain.OutputHash ? VerificationResult.Fail : VerificationResult.Ok;
        }
    }
}