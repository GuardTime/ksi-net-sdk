namespace Guardtime.KSI.Signature.Verification.Rule
{
    public interface IRule
    {
        VerificationResult Verify(VerificationContext context);
    }
}
