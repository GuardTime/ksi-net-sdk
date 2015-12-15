using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule verifies calendar hash chain aggregation time equality to last aggregation hash chain aggregation time.
    ///     Without calendar authentication record <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class CalendarHashChainAggregationTimeRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);
            CalendarHashChain calendarHashChain = GetCalendarHashChain(signature, true);

            // If calendar hash chain is missing, verification successful
            if (calendarHashChain == null)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            ReadOnlyCollection<AggregationHashChain> aggregationHashChains = GetAggregationHashChains(signature, false);
            ulong aggregationTime = aggregationHashChains[aggregationHashChains.Count - 1].AggregationTime;

            return aggregationTime != calendarHashChain.AggregationTime
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int04)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}