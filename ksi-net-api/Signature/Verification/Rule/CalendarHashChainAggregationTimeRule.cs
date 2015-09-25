using System;
using System.Collections.ObjectModel;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule verifies calendar hash chain aggregation time equality to last aggregation hash chain aggregation time.
    ///     Without calendar authentication record <see cref="VerificationResult.Ok" /> is returned.
    /// </summary>
    public sealed class CalendarHashChainAggregationTimeRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
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
                throw new KsiVerificationException("Signature cannot be null");
            }

            // If calendar hash chain is missing, verification successful
            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;
            if (calendarHashChain == null)
            {
                return VerificationResult.Ok;
            }

            ReadOnlyCollection<AggregationHashChain> aggregationHashChainCollection =
                context.Signature.GetAggregationHashChains();
            if (aggregationHashChainCollection == null || aggregationHashChainCollection.Count == 0)
            {
                throw new KsiVerificationException("Aggregation hash chains missing in KSI signature");
            }

            ulong aggregationTime =
                aggregationHashChainCollection[aggregationHashChainCollection.Count - 1].AggregationTime;

            if (aggregationTime != calendarHashChain.AggregationTime)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}