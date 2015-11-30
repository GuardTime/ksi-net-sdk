using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that aggregation hash chain times are consistent. It means that previous aggregation hash chain
    ///     aggregation time equals to current one.
    /// </summary>
    public sealed class AggregationHashChainTimeConsistencyRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            ReadOnlyCollection<AggregationHashChain> aggregationHashChains = GetAggregationHashChains(GetSignature(context), true);
            ulong? time = null;

            foreach (AggregationHashChain aggregationHashChain in aggregationHashChains)
            {
                if (time == null)
                {
                    time = aggregationHashChain.AggregationTime;
                    continue;
                }

                if (aggregationHashChain.AggregationTime == time)
                {
                    continue;
                }

                Logger.Warn("Previous aggregation hash chain aggregation time {0} does not match current aggregation time {1}", time, aggregationHashChain.AggregationTime);
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int02);
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}