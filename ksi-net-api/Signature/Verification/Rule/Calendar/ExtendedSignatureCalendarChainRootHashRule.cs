using System;

namespace Guardtime.KSI.Signature.Verification.Rule.Calendar
{
    public sealed class ExtendedSignatureCalendarChainRootHashRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            CalendarHashChain calendarHashChain = context.CalendarHashChain;
            if (calendarHashChain == null)
            {
                throw new InvalidOperationException("Invalid calendar hash chain: null");
            }

            CalendarHashChain extendedSignatureCalendarHashChain = context.GetExtendedTimeCalendarHashChain(calendarHashChain.PublicationData.PublicationTime);
            if (calendarHashChain.OutputHash != extendedSignatureCalendarHashChain.OutputHash)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}