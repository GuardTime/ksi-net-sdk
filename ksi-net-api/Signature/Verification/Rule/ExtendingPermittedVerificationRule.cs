using System;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class ExtendingPermittedVerificationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify"/>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            return context.IsExtendingAllowed ? VerificationResult.Ok : VerificationResult.Na;
        }
    }
}