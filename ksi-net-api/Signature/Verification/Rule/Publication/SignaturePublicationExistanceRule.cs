namespace Guardtime.KSI.Signature.Verification.Rule.Publication
{
    public sealed class SignaturePublicationExistanceRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            return context.PublicationRecord == null ? VerificationResult.Na : VerificationResult.Ok;
        }
    }
}