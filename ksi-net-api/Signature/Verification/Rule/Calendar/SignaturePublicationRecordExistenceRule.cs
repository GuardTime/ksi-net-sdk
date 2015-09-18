namespace Guardtime.KSI.Signature.Verification.Rule.Calendar
{
    public sealed class SignaturePublicationRecordExistenceRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            if (context.PublicationRecord == null)
            {
                // TODO: maybe should fail
                return VerificationResult.Na;
            }

            return VerificationResult.Ok;
        }
    }
}