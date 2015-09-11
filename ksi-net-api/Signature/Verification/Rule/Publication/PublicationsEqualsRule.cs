namespace Guardtime.KSI.Signature.Verification.Rule.Publication
{
    public sealed class PublicationsEqualsRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            return context.UserPublication == context.PublicationRecord ? VerificationResult.Ok : VerificationResult.Na;
        }
    }
}