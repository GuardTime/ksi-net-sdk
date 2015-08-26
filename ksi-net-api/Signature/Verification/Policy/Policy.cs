
using Guardtime.KSI.Signature.Verification.Rule;
using System;
using System.Collections.Generic;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    public class Policy : IPolicy
    {
        private readonly List<IRule> rules = new List<IRule>();

        public Policy()
        {
            // TODO: Check signature in constructor or above that
            rules.Add(new AggregationChainInputHashVerificationRule());
            rules.Add(new AggregationHashChainConsistencyRule());
            rules.Add(new AggregationHashChainTimeConsistencyRule());

            rules.Add(new CalendarHashChainInputHashVerificationRule());
            rules.Add(new CalendarHashChainAggregationTimeRule());
            rules.Add(new CalendarHashChainRegistrationTimeRule());
        }

        public bool Verify(VerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            for (int i = 0; i < rules.Count; i++)
            {
                Console.WriteLine("Rule {0}: {1}", rules[i].GetType().Name, rules[i].Verify(context));
            }

            return true;
        }


    }
}
