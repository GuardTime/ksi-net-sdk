namespace Guardtime.KSI.Signature.Verification.Rule.Publication
{
    public sealed class SignatureExtendingPermissionRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            return context.ExtendingAllowed ? VerificationResult.Ok : VerificationResult.Na;
        }
    }
}