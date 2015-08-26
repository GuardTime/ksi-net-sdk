using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Signature.Verification
{
    public interface IVerificationContext
    {
        DataHash DocumentHash
        {
            get;
        }

        KsiSignature Signature
        {
            get;
        }
    }
}