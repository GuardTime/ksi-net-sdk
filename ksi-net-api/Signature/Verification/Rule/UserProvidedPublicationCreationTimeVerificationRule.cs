namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks that signature is created before user provided publication.
    /// </summary>
    public sealed class UserProvidedPublicationCreationTimeVerificationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            ulong registrationTime = GetCalendarHashChain(GetSignature(context)).RegistrationTime;
            ulong userPublicationTime = GetUserPublication(context).PublicationTime;

            return registrationTime >= userPublicationTime
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Na, VerificationError.Gen02)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}