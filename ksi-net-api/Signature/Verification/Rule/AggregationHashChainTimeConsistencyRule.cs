using System;
using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Aggregation hash chain time consistency verification rule.
    /// </summary>
    public sealed class AggregationHashChainTimeConsistencyRule : IRule
    {
        private IRule rule;

        /// <summary>
        /// Verify given context with rule.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>verification result</returns>
        public override VerificationResult Verify(VerificationContext context)
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
                    return VerificationResult.Fail;
                }

            }

            return VerificationResult.Ok;
        }
    }
}
