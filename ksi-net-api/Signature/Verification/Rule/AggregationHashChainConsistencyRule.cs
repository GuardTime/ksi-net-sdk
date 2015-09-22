using System;
using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Aggregation hash chain consistency verification VerificationRule.
    /// </summary>
    public sealed class AggregationHashChainConsistencyRule : VerificationRule
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

            ReadOnlyCollection<AggregationHashChain> aggregationHashChainCollection = context.Signature.GetAggregationHashChains();
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
