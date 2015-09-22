
using Guardtime.KSI.Signature.Verification.Rule;
using System;
using System.Collections.Generic;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    /// Internal verification polcy.
    /// </summary>
    public class InternalVerificationPolicy : VerificationPolicy
    {
        /// <summary>
        /// Create internal verification policy and add rules to it.
        /// </summary>
        public InternalVerificationPolicy()
        {
            // Verify aggregation chain
            _firstRule = new AggregationChainInputHashVerificationRule()
                .OnSuccess(new AggregationHashChainConsistencyRule()
                    .OnSuccess(new AggregationHashChainTimeConsistencyRule()
                        .OnSuccess(
                            // If present verify calendar hash chain
                            new CalendarHashChainInputHashVerificationRule()
                                .OnSuccess(new CalendarHashChainAggregationTimeRule()
                                    .OnSuccess(new CalendarHashChainRegistrationTimeRule()
                                        .OnSuccess(
                                            // If present verify calendar authentication record
                                            new CalendarAuthenticationRecordAggregationHashRule()
                                                .OnSuccess(new CalendarAuthenticationRecordAggregationTimeRule()
                                                    .OnSuccess(
                                                        // If present verify publication record
                                                        new SignaturePublicationRecordPublicationHashRule()
                                                            .OnSuccess(new SignaturePublicationRecordPublicationTimeRule())))))))));
        }
    }
}
