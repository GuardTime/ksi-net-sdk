using System;
using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public class AggregationHashChainTimeConsistencyRule : IRule
    {
        
        public VerificationResult Verify(VerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            ReadOnlyCollection<AggregationHashChain> aggregationHashChainCollection = context.GetAggregationHashChains();
            if (aggregationHashChainCollection == null)
            {
                throw new ArgumentException("Invalid aggregation hash chains in context signature: null", "context");
            }

            ulong? time = null;
            for (int i = 0; i < aggregationHashChainCollection.Count; i++)
            {
                if (time == null)
                {
                    time = aggregationHashChainCollection[i].AggregationTime;
                    continue;
                }

                if (aggregationHashChainCollection[i].AggregationTime != time)
                {
                    // TODO: Correct logging
                    Console.WriteLine("Previous aggregation hash chain aggregation time {0} does not match current aggregation time {1}", time, aggregationHashChainCollection[i].AggregationTime);
                    return VerificationResult.FAIL;
                }

            }



            return VerificationResult.OK;
        }
    }
}
