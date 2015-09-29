using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
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
                throw new KsiException("Invalid context: null.");
            }
            
            VerificationRule verificationRule = FirstRule;
            List<VerificationResult> verificationResults = new List<VerificationResult>();
            while (verificationRule != null)
            {
                VerificationResult result = verificationRule.Verify(context);
                verificationResults.Add(result);
                verificationRule = verificationRule.NextRule(result.ResultCode);
            }

            return new VerificationResult(GetType().Name, verificationResults);
        }
    }
}