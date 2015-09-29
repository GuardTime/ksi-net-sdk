using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks if publications file contains certificate with certificate id contained in calendar authentication
    ///     record.
    /// </summary>
    public sealed class CertificateExistenceRule : VerificationRule
    {
        /// <summary>
        /// Rule name.
        /// </summary>
        public const string RuleName = "CertificateExistenceRule";

        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new KsiException("Invalid verification context: null.");
            }

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature in context: null.");
            }

            if (context.PublicationsFile == null)
            {
                throw new KsiVerificationException("Invalid publications file in context: null.");
            }

            CalendarAuthenticationRecord calendarAuthenticationRecord = context.Signature.CalendarAuthenticationRecord;
            if (calendarAuthenticationRecord == null)
            {
                throw new KsiVerificationException("Invalid calendar authentication record in KSI signature: null.");
            }

            SignatureData signatureData = calendarAuthenticationRecord.SignatureData;
            if (context.PublicationsFile.FindCertificateById(signatureData.CertificateId) == null)
            {
                return new VerificationResult(RuleName, VerificationResultCode.Fail, VerificationError.Key01);
            }

            return new VerificationResult(RuleName, VerificationResultCode.Ok);
        }
    }
}