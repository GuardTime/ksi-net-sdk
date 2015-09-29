using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that signature is created before user provided publication.
    /// </summary>
    public sealed class UserProvidedPublicationCreationTimeVerificationRule : VerificationRule
    {
        public const string RuleName = "UserProvidedPublicationCreationTimeVerificationRule";

        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new KsiException("Invalid verification context: null.");
            }

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null.");
            }

            if (context.Signature.CalendarHashChain == null)
            {
                throw new KsiVerificationException("Invalid calendar hash chain in KSI signature: null.");
            }

            if (context.UserPublication == null)
            {
                throw new KsiVerificationException("Invalid user publication in context: null.");
            }

            ulong registrationTime = context.Signature.CalendarHashChain.RegistrationTime;
            ulong userPublicationTime = context.UserPublication.PublicationTime;

            if (registrationTime >= userPublicationTime)
            {
                return new VerificationResult(RuleName, VerificationResultCode.Na, VerificationError.Gen02);
            }

            return new VerificationResult(RuleName, VerificationResultCode.Ok);
        }
    }
}