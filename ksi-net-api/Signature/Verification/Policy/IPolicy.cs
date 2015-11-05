namespace Guardtime.KSI.Signature.Verification.Policy
{
    /// <summary>
    ///     Verification policy interface.
    /// </summary>
    public interface IPolicy
    {
        /// <summary>
        ///     Verify context.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>true if verification is successful</returns>
        bool Verify(VerificationContext context);
    }
}