using System;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class CertificateExistenceRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify"/>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (context.Signature == null)
            {
                // TODO: Better exception
                throw new InvalidOperationException("Signature cannot be null");
            }

            CalendarAuthenticationRecord calendarAuthenticationRecord = context.Signature.CalendarAuthenticationRecord;
            if (calendarAuthenticationRecord == null)
            {
                throw new InvalidOperationException("Invalid calendar authentication record: null");
            }

            SignatureData signatureData = calendarAuthenticationRecord.SignatureData;
            
            if (context.PublicationsFile == null)
            {
                throw new InvalidOperationException("Invalid publications file: null");
            }

            if (context.PublicationsFile.FindCertificateById(signatureData.CertificateId) == null)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}