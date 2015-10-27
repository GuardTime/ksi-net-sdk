using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    ///     Policy for verifying KSI signature with calendar.
    /// </summary>
    public class CalendarBasedVerificationPolicy : VerificationPolicy
    {
        /// <summary>
        ///     Create calendar based verification policy with given rules.
        /// </summary>
        public CalendarBasedVerificationPolicy()
        {
            ExtendedSignatureCalendarChainInputHashRule extendedSignatureCalendarChainInputHashRule =
                new ExtendedSignatureCalendarChainInputHashRule();
            ExtendedSignatureCalendarChainAggregationTimeRule extendedSignatureCalendarChainAggregationTimeRule =
                new ExtendedSignatureCalendarChainAggregationTimeRule();

            FirstRule = new InternalVerificationPolicy()
                .OnSuccess(new CalendarHashChainExistenceRule()
                    .OnSuccess(
                        new SignaturePublicationRecordExistenceRule()
                            .OnSuccess(
                                new ExtendedSignatureCalendarChainRootHashRule()
                                    .OnSuccess(
                                        extendedSignatureCalendarChainInputHashRule
                                            .OnSuccess(extendedSignatureCalendarChainAggregationTimeRule)))
                            .OnNa(
                                new ExtendedSignatureAggregationChainRightLinksMatchesRule()
                                    .OnSuccess(
                                        extendedSignatureCalendarChainInputHashRule
                                            .OnSuccess(extendedSignatureCalendarChainAggregationTimeRule))))
                    .OnNa(
                        extendedSignatureCalendarChainInputHashRule
                            .OnSuccess(extendedSignatureCalendarChainAggregationTimeRule)));
        }
    }
}