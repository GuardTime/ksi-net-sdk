using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule for checking if KSI signature contains calendar hash chain.
    ///     Used for key-based and publication-based verification policies.
    /// </summary>
    public sealed class CalendarHashChainExistenceRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            return GetSignature(context).CalendarHashChain == null
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Na, VerificationError.Gen02)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}