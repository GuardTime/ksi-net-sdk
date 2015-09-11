namespace Guardtime.KSI.Signature.Verification
{
    /// <summary>
    /// Verification results.
    /// </summary>
    public enum VerificationResult
    {
        /// <summary>
        /// Verification result succeeded.
        /// </summary>
        Ok = 0,
        /// <summary>
        /// Verification result failed.
        /// </summary>
        Fail = 1,
        /// <summary>
        /// Verification result undefined
        /// </summary>
        Na = 2
    }
}
