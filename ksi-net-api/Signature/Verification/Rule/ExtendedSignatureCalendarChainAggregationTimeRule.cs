using System;
using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class ExtendedSignatureCalendarChainAggregationTimeRule : VerificationRule
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

            ReadOnlyCollection<AggregationHashChain> aggregationHashChainCollection = context.Signature.GetAggregationHashChains();
            if (aggregationHashChainCollection == null)
            {
                throw new InvalidOperationException("Invalid aggregation hash chains in context signature: null");
            }

            ulong? aggregationTime = null;
            if (aggregationHashChainCollection.Count > 0)
            {
                aggregationTime = aggregationHashChainCollection[aggregationHashChainCollection.Count - 1].AggregationTime;
            }

            if (aggregationTime == null)
            {
                throw new InvalidOperationException("Invalid aggregation time: null");
            }

            if (aggregationTime != extendedCalendarHashChain.AggregationTime)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}