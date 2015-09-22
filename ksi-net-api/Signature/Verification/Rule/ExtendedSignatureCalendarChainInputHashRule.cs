using System;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class ExtendedSignatureCalendarChainInputHashRule : VerificationRule
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
                // TODO: Better exception
                throw new InvalidOperationException("Invalid calendar hash chain: null");
            }

            CalendarHashChain extendedCalendarHashChain = calendarHashChain.PublicationData == null ? 
                context.GetExtendedLatestCalendarHashChain() : 
                context.GetExtendedTimeCalendarHashChain(calendarHashChain.PublicationData.PublicationTime);

            if (extendedCalendarHashChain == null)
            {
                throw new InvalidOperationException("Invalid extended calendar hash chain: null");
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