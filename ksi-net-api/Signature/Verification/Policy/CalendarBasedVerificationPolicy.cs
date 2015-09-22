
using Guardtime.KSI.Signature.Verification.Rule;
using System;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    /// Internal verification polcy.
    /// </summary>
    public class CalendarBasedVerificationPolicy : VerificationPolicy
    {
        /// <summary>
        /// Create internal verification policy and add rules to it.
        /// </summary>
        public CalendarBasedVerificationPolicy()
        {
            ExtendedSignatureCalendarChainInputHashRule extendedSignatureCalendarChainInputHashRule = new ExtendedSignatureCalendarChainInputHashRule();
            ExtendedSignatureCalendarChainAggregationTimeRule extendedSignatureCalendarChainAggregationTimeRule = new ExtendedSignatureCalendarChainAggregationTimeRule();

            // Check for internal verification
            _firstRule = new CalendarHashChainExistenceRule()
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
                        .OnSuccess(extendedSignatureCalendarChainAggregationTimeRule));
        }

    }
}
