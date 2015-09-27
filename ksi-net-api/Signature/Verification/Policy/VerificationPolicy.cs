using System;
using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    ///     Verification policy to verify set of verification rules.
    /// </summary>
    public abstract class VerificationPolicy : VerificationRule
    {
        /// <summary>
        ///     First rule to verify.
        /// </summary>
        protected VerificationRule FirstRule;

        /// <summary>
        ///     Verify given context with verification policy.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>verification result</returns>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            VerificationRule verificationRule = FirstRule ?? Empty;
            while (verificationRule != null)
            {
                VerificationResult result = verificationRule.Verify(context);
                Console.WriteLine("VerificationRule {0}: {1}", verificationRule.GetType().Name, result);
                verificationRule = verificationRule.NextRule(result);
            }

            return VerificationResult.Ok;
        }
    }
}