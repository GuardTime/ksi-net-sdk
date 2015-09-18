using System;
using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule.Calendar
{
    public sealed class ExtendedSignatureCalendarChainAggregationTimeRule : IRule
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

            ReadOnlyCollection<AggregationHashChain> aggregationHashChainCollection = context.GetAggregationHashChains();
            if (aggregationHashChainCollection == null)
            {
                throw new ArgumentException("Invalid aggregation hash chains in context signature: null", "context");
            }

            ulong? aggregationTime = null;
            if (aggregationHashChainCollection.Count > 0)
            {
                aggregationTime = aggregationHashChainCollection[aggregationHashChainCollection.Count - 1].AggregationTime;
            }

            if (aggregationTime == null)
            {
                throw new ArgumentException("Invalid aggregation time: null", "context");
            }

            if (aggregationTime != extendedCalendarHashChain.AggregationTime)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}