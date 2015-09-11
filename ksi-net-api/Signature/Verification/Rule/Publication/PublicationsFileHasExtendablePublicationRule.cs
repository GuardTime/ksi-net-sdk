namespace Guardtime.KSI.Signature.Verification.Rule.Publication
{
    public sealed class PublicationsFileHasExtendablePublicationRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            return context.UserPublication == null ? VerificationResult.Na : VerificationResult.Ok;
        }
    }
}