using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule checks if publications file contains certificate with certificate id contained in calendar authentication
    ///     record.
    /// </summary>
    public sealed class CertificateExistenceRule : VerificationRule
    {
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
                throw new KsiVerificationException("Signature cannot be null");
            }

            if (context.PublicationsFile == null)
            {
                throw new KsiVerificationException("Invalid publications file: null");
            }

            CalendarAuthenticationRecord calendarAuthenticationRecord = context.Signature.CalendarAuthenticationRecord;
            if (calendarAuthenticationRecord == null)
            {
                throw new KsiVerificationException("Invalid calendar authentication record: null");
            }

            SignatureData signatureData = calendarAuthenticationRecord.SignatureData;
            if (context.PublicationsFile.FindCertificateById(signatureData.CertificateId) == null)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}