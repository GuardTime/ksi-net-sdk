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
            // TODO: Log exception
            return context.PublicationsFile.FindCertificateById(signatureData.GetCertificateId()) == null
                ? new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Key01)
                : new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}