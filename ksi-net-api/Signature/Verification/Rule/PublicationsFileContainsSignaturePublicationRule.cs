using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Trust;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks if publications file contains signature publication.
    /// </summary>
    public sealed class PublicationsFileContainsSignaturePublicationRule : VerificationRule
    {
        /// <summary>
        ///     Rule name.
        /// </summary>
        public const string RuleName = "PublicationsFileContainsSignaturePublicationRule";

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

            IKsiTrustProvider publicationsFile = context.PublicationsFile;
            if (publicationsFile == null)
            {
                throw new KsiVerificationException("Invalid publications file in context: null.");
            }

            if (context.Signature.PublicationRecord == null)
            {
                throw new KsiVerificationException("Invalid publications record in KSI signature: null.");
            }

            if (!publicationsFile.Contains(context.Signature.PublicationRecord))
            {
                return new VerificationResult(RuleName, VerificationResultCode.Na, VerificationError.Gen02);
            }

            return new VerificationResult(RuleName, VerificationResultCode.Ok);
        }
    }
}