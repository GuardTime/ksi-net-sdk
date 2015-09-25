using System;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class UserProvidedPublicationCreationTimeVerificationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="ArgumentNullException">thrown if context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null");
            }

            if (context.Signature.CalendarHashChain == null)
            {
                throw new KsiVerificationException("Invalid calendar hash chain in signature: null");
            }

            if (context.UserPublication == null)
            {
                throw new KsiVerificationException("Invalid user publication in context: null");
            }

            ulong registrationTime = context.Signature.CalendarHashChain.RegistrationTime;
            ulong userPublicationTime = context.UserPublication.PublicationTime;

            if (registrationTime >= userPublicationTime)
            {
                return VerificationResult.Na;
            }

            return VerificationResult.Ok;
        }
    }
}