using System;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class UserProvidedPublicationCreationTimeVerificationRule : VerificationRule
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

            if (context.Signature.CalendarHashChain == null)
            {
                throw new InvalidOperationException("Invalid calendar hash chain: null");
            }

            if (context.UserPublication == null)
            {
                throw new InvalidOperationException("Invalid user publication: null");
            }

            ulong registrationTime = context.Signature.CalendarHashChain.RegistrationTime;
            ulong userPublicationTime = context.UserPublication.PublicationTime;

            if (registrationTime < userPublicationTime)
            {
                return VerificationResult.Na;
            }

            return VerificationResult.Ok;
        }
    }
}