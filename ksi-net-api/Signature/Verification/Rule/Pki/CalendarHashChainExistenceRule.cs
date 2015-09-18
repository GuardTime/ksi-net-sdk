namespace Guardtime.KSI.Signature.Verification.Rule.Pki
{
    public sealed class CalendarHashChainExistenceRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            return context.CalendarHashChain == null ? VerificationResult.Na : VerificationResult.Ok;
        }
    }
}