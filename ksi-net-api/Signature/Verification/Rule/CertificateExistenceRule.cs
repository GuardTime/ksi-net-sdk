namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks if publications file contains certificate with certificate id contained in calendar authentication
    ///     record.
    /// </summary>
    public sealed class CertificateExistenceRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            CalendarAuthenticationRecord calendarAuthenticationRecord = GetCalendarAuthenticationRecord(GetSignature(context));
            SignatureData signatureData = calendarAuthenticationRecord.SignatureData;

            return GetPublicationsFile(context).FindCertificateById(signatureData.GetCertificateId()) == null
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Key01)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}