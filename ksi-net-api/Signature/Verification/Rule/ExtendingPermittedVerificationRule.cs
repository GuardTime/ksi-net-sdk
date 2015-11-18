using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that extending is permitted by user.
    /// </summary>
    public sealed class ExtendingPermittedVerificationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            CheckVerificationContext(context);

            return context.IsExtendingAllowed
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Ok)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Na, VerificationError.Gen02);
        }
    }
}