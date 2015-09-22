﻿using System;
using System.Collections.ObjectModel;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Calendar hash chain aggregation time verification VerificationRule.
    /// </summary>
    public sealed class CalendarHashChainAggregationTimeRule : VerificationRule
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

            // If calendar hash chain is missing, verification successful
            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;
            if (calendarHashChain == null)
            {
                return VerificationResult.Ok;
            }

            ReadOnlyCollection<AggregationHashChain> aggregationHashChainCollection = context.Signature.GetAggregationHashChains();
            if (aggregationHashChainCollection == null)
            {
                throw new ArgumentException("Invalid aggregation hash chains in context signature: null", "context");
            }

            ulong? aggregationTime = null;
            if (aggregationHashChainCollection.Count > 0)
            {
                aggregationTime = aggregationHashChainCollection[aggregationHashChainCollection.Count - 1].AggregationTime;
            }

            if (aggregationTime == null)
            {
                throw new ArgumentException("Invalid aggregation time: null", "context");
            }

            if (aggregationTime != calendarHashChain.AggregationTime)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}
