

namespace Guardtime.KSI.Signature.Verification.Policy
{
    public interface IPolicy
    {
        bool Verify(VerificationContext context);   
    }
}
