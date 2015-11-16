using System.Collections.ObjectModel;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule verifies calendar hash chain aggregation time equality to last aggregation hash chain aggregation time.
    ///     Without calendar authentication record <see cref="VerificationResultCode.Ok" /> is returned.
    /// </summary>
    public sealed class CalendarHashChainAggregationTimeRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new KsiException("Invalid verification context: null.");
            }

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null.");
            }

            // If calendar hash chain is missing, verification successful
            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;
            if (calendarHashChain == null)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }

            ReadOnlyCollection<AggregationHashChain> aggregationHashChainCollection =
                context.Signature.GetAggregationHashChains();
            if (aggregationHashChainCollection == null || aggregationHashChainCollection.Count == 0)
            {
                throw new KsiVerificationException("Aggregation hash chains are missing from KSI signature.");
            }

            ulong aggregationTime =
                aggregationHashChainCollection[aggregationHashChainCollection.Count - 1].AggregationTime;

            if (aggregationTime != calendarHashChain.AggregationTime)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int04);
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}