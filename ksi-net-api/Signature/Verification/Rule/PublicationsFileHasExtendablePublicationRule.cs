using System;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class PublicationsFileHasExtendablePublicationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify"/>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (context.Signature == null)
            {
                // TODO: Better exception
                throw new InvalidOperationException("Signature cannot be null");
            }

            return context.UserPublication == null ? VerificationResult.Na : VerificationResult.Ok;
        }
    }
}