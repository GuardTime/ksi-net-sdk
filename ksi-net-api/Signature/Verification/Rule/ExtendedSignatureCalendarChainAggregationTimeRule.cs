using System;
using System.Collections.ObjectModel;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class ExtendedSignatureCalendarChainAggregationTimeRule : VerificationRule
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
                throw new KsiVerificationException("Signature cannot be null");
            }

            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;
            if (calendarHashChain == null)
            {
                throw new KsiVerificationException("Invalid calendar hash chain in context signature: null");
            }

            CalendarHashChain extendedCalendarHashChain = calendarHashChain.PublicationData == null
                ? context.GetExtendedLatestCalendarHashChain()
                : context.GetExtendedTimeCalendarHashChain(calendarHashChain.PublicationData.PublicationTime);

            if (extendedCalendarHashChain == null)
            {
                throw new KsiVerificationException(
                    "Invalid extended calendar hash chain from context extension function: null");
            }

            ReadOnlyCollection<AggregationHashChain> aggregationHashChainCollection =
                context.Signature.GetAggregationHashChains();
            ulong aggregationTime =
                aggregationHashChainCollection[aggregationHashChainCollection.Count - 1].AggregationTime;

            if (aggregationTime != extendedCalendarHashChain.AggregationTime)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}