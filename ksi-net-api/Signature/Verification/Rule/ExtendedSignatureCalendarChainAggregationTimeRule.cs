using System.Collections.ObjectModel;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that extended signature contains correct aggregation time.
    /// </summary>
    public sealed class ExtendedSignatureCalendarChainAggregationTimeRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);
            CalendarHashChain calendarHashChain = GetCalendarHashChain(signature);

            CalendarHashChain extendedCalendarHashChain = calendarHashChain.PublicationData == null
                ? context.GetExtendedLatestCalendarHashChain()
                : context.GetExtendedTimeCalendarHashChain(calendarHashChain.PublicationData.PublicationTime);

            if (extendedCalendarHashChain == null)
            {
                throw new KsiVerificationException("Received invalid extended calendar hash chain from context extension function: null.");
            }

            ReadOnlyCollection<AggregationHashChain> aggregationHashChainCollection = GetAggregationHashChains(signature, false);
            ulong aggregationTime = aggregationHashChainCollection[aggregationHashChainCollection.Count - 1].AggregationTime;

            return aggregationTime != extendedCalendarHashChain.AggregationTime
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Cal03)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}