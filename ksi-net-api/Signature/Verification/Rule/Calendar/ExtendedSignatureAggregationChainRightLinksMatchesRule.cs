using System;
using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule.Calendar
{
    public sealed class ExtendedSignatureAggregationChainRightLinksMatchesRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            CalendarHashChain calendarHashChain = context.CalendarHashChain;
            if (calendarHashChain == null)
            {
                // TODO: Better exception
                throw new InvalidOperationException("Invalid calendar hash chain: null");
            }

            CalendarHashChain extendedCalendarHashChain = context.GetExtendedTimeCalendarHashChain(calendarHashChain.PublicationData.PublicationTime);

            if (!calendarHashChain.AreRightLinksEqual(extendedCalendarHashChain))
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}