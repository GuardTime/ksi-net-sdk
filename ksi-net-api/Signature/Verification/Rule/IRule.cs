namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    /// Verification rule interface.
    /// </summary>
    public interface IRule
    {
        /// <summary>
        /// Verify given context with rule.
        /// </summary>
        /// <param name="context">verification context</param>
        /// <returns>verification result</returns>
        VerificationResult Verify(VerificationContext context);
    }
}
