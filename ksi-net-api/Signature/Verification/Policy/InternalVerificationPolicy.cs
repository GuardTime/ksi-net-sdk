
using Guardtime.KSI.Signature.Verification.Rule;
using System;
using System.Collections.Generic;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    public class InternalVerificationPolicy : IPolicy
    {
        private readonly List<IRule> _rules = new List<IRule>();

        public InternalVerificationPolicy()
        {
            // TODO: Check signature in constructor or above that
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
