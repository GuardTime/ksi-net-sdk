using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that extending is permitted by user.
    /// </summary>
    public sealed class ExtendingPermittedVerificationRule : VerificationRule
    {
        /// <summary>
        ///     Rule name.
        /// </summary>
        public const string RuleName = "ExtendingPermittedVerificationRule";

        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new KsiException("Invalid verification context: null.");
            }

            return context.IsExtendingAllowed
                ? new VerificationResult(RuleName, VerificationResultCode.Ok)
                : new VerificationResult(RuleName, VerificationResultCode.Na, VerificationError.Gen02);
        }
    }
}