using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that user provided publication equals to publication in KSI signature.
    /// </summary>
    public sealed class UserProvidedPublicationVerificationRule : VerificationRule
    {
        /// <summary>
        ///     Rule name.
        /// </summary>
        public const string RuleName = "UserProvidedPublicationVerificationRule";

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

            if (context.UserPublication == null)
            {
                throw new KsiVerificationException("Invalid user publication in context: null.");
            }

            if (context.Signature.PublicationRecord == null)
            {
                throw new KsiVerificationException("Invalid publication record in KSI signature: null.");
            }

            return context.UserPublication == context.Signature.PublicationRecord.PublicationData
                ? new VerificationResult(RuleName, VerificationResultCode.Ok)
                : new VerificationResult(RuleName, VerificationResultCode.Na, VerificationError.Gen02);
        }
    }
}