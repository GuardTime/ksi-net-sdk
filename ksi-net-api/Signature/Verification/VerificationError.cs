namespace Guardtime.KSI.Signature.Verification
{
    /// <summary>
    /// Verification errors.
    /// </summary>
    public enum VerificationError
    {
        /// <summary>
        /// No resulting error.
        /// </summary>
        NoError = 0x0,
        /// <summary>
        /// Invalid aggregation hash chain error.
        /// </summary>
        InvalidAggregationHashChain = 0x1
    }
}