namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule verifies that KSI signature contains calendar authentication record.
    /// </summary>
    public sealed class CalendarAuthenticationRecordExistenceRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            return GetSignature(context).CalendarAuthenticationRecord != null
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Ok)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Na, VerificationError.Gen02);
        }
    }
}