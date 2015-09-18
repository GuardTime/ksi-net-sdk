using System;

namespace Guardtime.KSI.Signature.Verification.Rule.Calendar
{
    public sealed class ExtendedSignatureCalendarChainInputHashRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            CalendarHashChain calendarHashChain = context.CalendarHashChain;
            if (calendarHashChain == null)
            {
                // TODO: Better exception
                throw new InvalidOperationException("Invalid calendar hash chain: null");
            }

            CalendarHashChain extendedCalendarHashChain = calendarHashChain.PublicationData == null ? 
                context.GetExtendedLatestCalendarHashChain() : 
                context.GetExtendedTimeCalendarHashChain(calendarHashChain.PublicationData.PublicationTime);

            if (context.GetAggregationHashChainRootHash() != extendedCalendarHashChain.InputHash)
            {
                // TODO: Log
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}