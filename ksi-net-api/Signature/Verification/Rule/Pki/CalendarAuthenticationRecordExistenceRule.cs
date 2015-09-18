namespace Guardtime.KSI.Signature.Verification.Rule.Pki
{
    public sealed class CalendarAuthenticationRecordExistenceRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            return context.CalendarAuthenticationRecord != null ? VerificationResult.Ok : VerificationResult.Na;
        }
    }
}