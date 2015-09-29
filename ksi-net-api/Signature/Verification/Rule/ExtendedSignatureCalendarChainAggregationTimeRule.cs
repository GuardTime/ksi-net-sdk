using System.Collections.ObjectModel;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that extended signature contains correct aggregation time.
    /// </summary>
    public sealed class ExtendedSignatureCalendarChainAggregationTimeRule : VerificationRule
    {
        /// <summary>
        /// Rule name.
        /// </summary>
        public const string RuleName = "ExtendedSignatureCalendarChainAggregationTimeRule";

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

            CalendarHashChain calendarHashChain = context.Signature.CalendarHashChain;
            if (calendarHashChain == null)
            {
                throw new KsiVerificationException("Invalid calendar hash chain in KSI signature: null.");
            }

            CalendarHashChain extendedCalendarHashChain = calendarHashChain.PublicationData == null
                ? context.GetExtendedLatestCalendarHashChain()
                : context.GetExtendedTimeCalendarHashChain(calendarHashChain.PublicationData.PublicationTime);

            if (extendedCalendarHashChain == null)
            {
                throw new KsiVerificationException(
                    "Received invalid extended calendar hash chain from context extension function: null.");
            }

            ReadOnlyCollection<AggregationHashChain> aggregationHashChainCollection =
                context.Signature.GetAggregationHashChains();
            ulong aggregationTime =
                aggregationHashChainCollection[aggregationHashChainCollection.Count - 1].AggregationTime;

            if (aggregationTime != extendedCalendarHashChain.AggregationTime)
            {
                return new VerificationResult(RuleName, VerificationResultCode.Fail, VerificationError.Cal03);
            }

            return new VerificationResult(RuleName, VerificationResultCode.Ok);
        }
    }
}