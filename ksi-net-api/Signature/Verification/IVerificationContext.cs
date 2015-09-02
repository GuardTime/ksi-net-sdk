using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Signature.Verification
{
    /// <summary>
    /// Verification context interface.
    /// </summary>
    public interface IVerificationContext
    {
        /// <summary>
        /// Get document hash.
        /// </summary>
        DataHash DocumentHash
        {
            get;
        }

        /// <summary>
        /// Get signature.
        /// </summary>
        KsiSignature Signature
        {
            get;
        }
    }
}