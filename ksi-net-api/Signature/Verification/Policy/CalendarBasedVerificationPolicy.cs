
using Guardtime.KSI.Signature.Verification.Rule;
using System;
using System.Diagnostics;
using Guardtime.KSI.Signature.Verification.Rule.Calendar;
using Guardtime.KSI.Signature.Verification.Rule.Pki;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    /// Internal verification polcy.
    /// </summary>
    public class CalendarBasedVerificationPolicy : IPolicy
    {
        private readonly IRule _startRule;

        /// <summary>
        /// Create internal verification policy and add rules to it.
        /// </summary>
        public CalendarBasedVerificationPolicy()
        {
            ExtendedSignatureCalendarChainInputHashRule extendedSignatureCalendarChainInputHashRule = new ExtendedSignatureCalendarChainInputHashRule();
            ExtendedSignatureCalendarChainAggregationTimeRule extendedSignatureCalendarChainAggregationTimeRule = new ExtendedSignatureCalendarChainAggregationTimeRule();

            // Check for internal verification
            _startRule = new CalendarHashChainExistenceRule()
                .OnSuccess(
                    new SignaturePublicationRecordExistenceRule()
                        .OnSuccess(
                            extendedSignatureCalendarChainInputHashRule
                                .OnSuccess(
                                    extendedSignatureCalendarChainInputHashRule
                                        .OnSuccess(extendedSignatureCalendarChainAggregationTimeRule)))
                        .OnNa(
                            new ExtendedSignatureAggregationChainRightLinksMatchesRule()
                                .OnSuccess(
                                    extendedSignatureCalendarChainInputHashRule
                                        .OnSuccess(extendedSignatureCalendarChainAggregationTimeRule)))
                .OnNa(
                    extendedSignatureCalendarChainInputHashRule
                        .OnSuccess(extendedSignatureCalendarChainAggregationTimeRule)));
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
