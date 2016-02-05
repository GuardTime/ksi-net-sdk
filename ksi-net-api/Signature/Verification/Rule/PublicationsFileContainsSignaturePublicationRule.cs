using Guardtime.KSI.Publication;
using Guardtime.KSI.Trust;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks if publications file contains signature publication.
    /// </summary>
    public sealed class PublicationsFileContainsSignaturePublicationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiTrustProvider publicationsFile = GetPublicationsFile(context);
            PublicationRecordInSignature publicationRecord = GetPublicationRecord(GetSignature(context));

            return !publicationsFile.Contains(publicationRecord)
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Na, VerificationError.Gen02)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}