using System;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class UserProvidedPublicationVerificationRule : VerificationRule
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

            if (context.UserPublication == null)
            {
                throw new InvalidOperationException("Invalid user publication: null");
            }

            if (context.Signature.PublicationRecord == null)
            {
                throw new InvalidOperationException("Invalid signature publication record: null");
            }

            return context.UserPublication == context.Signature.PublicationRecord.PublicationData ? VerificationResult.Ok : VerificationResult.Na;
        }
    }
}