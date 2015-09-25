using System;
using Guardtime.KSI.Signature.Verification.Rule;

namespace Guardtime.KSI.Signature.Verification.Policy
{
    public abstract class VerificationPolicy : VerificationRule
    {
        protected VerificationRule _firstRule;

        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            VerificationRule verificationRule = _firstRule ?? Empty;
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