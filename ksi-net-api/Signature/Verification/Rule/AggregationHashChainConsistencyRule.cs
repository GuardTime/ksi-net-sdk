using System;
using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Aggregation hash chain consistency verification rule.
    /// </summary>
    public sealed class AggregationHashChainConsistencyRule : IRule
    {

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

            AggregationHashChain.ChainResult chainResult = null;
            for (int i = 0; i < aggregationHashChainCollection.Count; i++)
            {
                
                if (chainResult == null)
                {
                    chainResult = new AggregationHashChain.ChainResult(0, aggregationHashChainCollection[0].InputHash);
                }

                if (aggregationHashChainCollection[i].InputHash != chainResult.Hash)
                {
                    // TODO: Correct logging
                    Console.WriteLine("Previous aggregation hash chain output hash {0} does not match current input hash {1}", chainResult.Hash, aggregationHashChainCollection[i].InputHash);
                    return VerificationResult.Fail;
                }

                chainResult = aggregationHashChainCollection[i].GetOutputHash(chainResult.Level);
            }

            return VerificationResult.Ok;
        }
    }
}
