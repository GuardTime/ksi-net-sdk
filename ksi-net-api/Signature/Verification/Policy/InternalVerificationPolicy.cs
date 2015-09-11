
using Guardtime.KSI.Signature.Verification.Rule;
using System;
using System.Collections.Generic;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    /// Internal verification polcy.
    /// </summary>
    public class InternalVerificationPolicy : IPolicy
    {
        private readonly List<IRule> _rules = new List<IRule>();
        private readonly IRule _startRule;

        /// <summary>
        /// Create internal verification policy and add rules to it.
        /// </summary>
        public InternalVerificationPolicy()
        {
            // Verify aggregation chain
            _startRule = new AggregationChainInputHashVerificationRule()
                .OnSuccess(new AggregationHashChainConsistencyRule()
                    .OnSuccess(new AggregationHashChainTimeConsistencyRule()
                        .OnSuccess(
                            // If present verify calendar hash chain
                            new CalendarHashChainInputHashVerificationRule()
                            .OnSuccess(new CalendarHashChainAggregationTimeRule()
                                .OnSuccess(new CalendarHashChainRegistrationTimeRule()
                                    .OnSuccess(
                                        // If present verify publication record
                                        new SignaturePublicationRecordPublicationTimeRule()
                                        .OnSuccess(new SignaturePublicationRecordPublicationHashRule())))))));

            
            // TODO: Add input hash verification
            //rules.add(new DocumentHashVerificationRule());
        }

        /// <summary>
        /// Verify context with set up rules.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>true if verification is successful</returns>
        public bool Verify(VerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            IRule rule = _startRule ?? IRule.Empty;
            while (rule != null)
            {
                VerificationResult result = rule.Verify(context);
                Console.WriteLine("Rule {0}: {1}", rule.GetType().Name, result);
                rule = rule.NextRule(result);
            }
 
            return true;
        }


    }
}
