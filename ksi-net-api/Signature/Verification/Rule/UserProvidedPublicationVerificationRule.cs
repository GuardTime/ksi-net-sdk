using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that user provided publication equals to publication in KSI signature.
    /// </summary>
    public sealed class UserProvidedPublicationVerificationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);

            if (signature.PublicationRecord == null)
            {
                throw new KsiVerificationException("Invalid publication record in KSI signature: null.");
            }

            PublicationData userPublication = GetUserPublication(context);
            PublicationData signaturePublication = GetPublicationRecord(signature).PublicationData;

            if (userPublication == signaturePublication)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
            }
            else
            {
                Logger.Info("User provided publication '{0}' does not equal to signature publication '{1}'", userPublication, signaturePublication);
                return new VerificationResult(GetRuleName(), VerificationResultCode.Na, VerificationError.Gen02);
            }
        }
    }
}