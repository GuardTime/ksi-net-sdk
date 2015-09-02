
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

        /// <summary>
        /// Create internal verification policy and add rules to it.
        /// </summary>
        public InternalVerificationPolicy()
        {
            // Verify aggregation hash chain
            _rules.Add(new AggregationChainInputHashVerificationRule());
            _rules.Add(new AggregationHashChainConsistencyRule());
            _rules.Add(new AggregationHashChainTimeConsistencyRule());

            // If present verify calendar hash chain
            _rules.Add(new CalendarHashChainInputHashVerificationRule());
            _rules.Add(new CalendarHashChainAggregationTimeRule());
            _rules.Add(new CalendarHashChainRegistrationTimeRule());

            // If present verify calendar authentication record
            _rules.Add(new CalendarAuthenticationRecordAggregationHashRule());
            _rules.Add(new CalendarAuthenticationRecordAggregationTimeRule());

            // If present verify publication record
            _rules.Add(new SignaturePublicationRecordPublicationHashRule());
            _rules.Add(new SignaturePublicationRecordPublicationTimeRule());

            //
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

            for (int i = 0; i < _rules.Count; i++)
            {
                Console.WriteLine("Rule {0}: {1}", _rules[i].GetType().Name, _rules[i].Verify(context));
            }

            return true;
        }


    }
}
