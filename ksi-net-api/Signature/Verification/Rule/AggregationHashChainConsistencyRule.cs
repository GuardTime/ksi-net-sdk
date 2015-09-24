using System;
using System.Collections.ObjectModel;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
 
    /// <summary>
    /// Rule verifies if all aggregation hash chains are consistent. e.g. previous aggregation hash chain output hash equals to current aggregation hash chain input hash.
    /// </summary>
    public sealed class AggregationHashChainConsistencyRule : VerificationRule
    {

        /// <see cref="VerificationRule.Verify"/>
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
                throw new KsiVerificationException("Invalid KSI signature: null");
            }

            ReadOnlyCollection<AggregationHashChain> aggregationHashChainCollection = context.Signature.GetAggregationHashChains();

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

                chainResult = aggregationHashChainCollection[i].GetOutputHash(chainResult);
            }

            return VerificationResult.Ok;
        }
    }
}
