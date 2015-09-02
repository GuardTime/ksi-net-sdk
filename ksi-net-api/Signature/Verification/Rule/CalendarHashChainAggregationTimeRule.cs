using System;
using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Calendar hash chain aggregation time verification rule.
    /// </summary>
    public class CalendarHashChainAggregationTimeRule : IRule
    {
        /// <summary>
        /// Verify given context with rule.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>verification result</returns>
        public VerificationResult Verify(VerificationContext context)
        {

            // If calendar hash chain is missing, verification successful
            CalendarHashChain calendarHashChain = context.CalendarHashChain;
            if (calendarHashChain == null)
            {
                return VerificationResult.Ok;
            }

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

            if (aggregationTime != calendarHashChain.AggregationTime)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}
