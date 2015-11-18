using System.Collections.ObjectModel;
using Guardtime.KSI.Exceptions;
using NLog;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that aggregation hash chain times are consistent. It means that previous aggregation hash chain
    ///     aggregation time equals to current one.
    /// </summary>
    public sealed class AggregationHashChainTimeConsistencyRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            ReadOnlyCollection<AggregationHashChain> aggregationHashChains = GetAggregationHashChains(GetSignature(context), true);
            ulong? time = null;

            for (int i = 0; i < aggregationHashChains.Count; i++)
            {
                if (time == null)
                {
                    time = aggregationHashChains[i].AggregationTime;
                    continue;
                }

                if (aggregationHashChains[i].AggregationTime == time)
                {
                    continue;
                }

                // TODO: Correct logging
                Logger.Error("Previous aggregation hash chain aggregation time {0} does not match current aggregation time {1}",time, aggregationHashChains[i].AggregationTime);
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int02);
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}