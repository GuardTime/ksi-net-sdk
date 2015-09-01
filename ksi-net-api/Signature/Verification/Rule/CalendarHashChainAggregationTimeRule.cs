using System;
using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public class CalendarHashChainAggregationTimeRule : IRule
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public VerificationResult Verify(VerificationContext context)
        {

            // If calendar hash chain is missing, verification successful
            CalendarHashChain calendarHashChain = context.CalendarHashChain;
            if (calendarHashChain == null)
            {
                return VerificationResult.OK;
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

            // TODO: Check if data exists in object before calling verify
            if (aggregationTime == null)
            {
                throw new ArgumentException("Invalid aggregation time: null", "context");
            }

            if (aggregationTime != calendarHashChain.AggregationTime)
            {
                return VerificationResult.FAIL;
            }

            return VerificationResult.OK;
        }
    }
}
