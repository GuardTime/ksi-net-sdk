namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that user has provided a publication.
    /// </summary>
    public sealed class UserProvidedPublicationExistenceRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            CheckVerificationContext(context);

            return context.UserPublication == null
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Na, VerificationError.Gen02)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}