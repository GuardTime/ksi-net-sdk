using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that user provided publication equals to publication in KSI signature.
    /// </summary>
    public sealed class UserProvidedPublicationVerificationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);

            if (signature.PublicationRecord == null)
            {
                throw new KsiVerificationException("Invalid publication record in KSI signature: null.");
            }

            return GetUserPublication(context) == GetPublicationRecord(signature).PublicationData
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Ok)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Na, VerificationError.Gen02);
        }
    }
}