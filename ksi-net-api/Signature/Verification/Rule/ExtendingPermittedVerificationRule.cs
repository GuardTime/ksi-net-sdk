using System;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class ExtendingPermittedVerificationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="ArgumentNullException">thrown if context is missing</exception>
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