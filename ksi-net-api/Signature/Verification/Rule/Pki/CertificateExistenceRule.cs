using System;

namespace Guardtime.KSI.Signature.Verification.Rule.Pki
{
    public sealed class CertificateExistenceRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            CalendarAuthenticationRecord calendarAuthenticationRecord = context.CalendarAuthenticationRecord;
            if (calendarAuthenticationRecord == null)
            {
                throw new InvalidOperationException("Invalid calendar authentication record: null");
            }

            SignatureData signatureData = calendarAuthenticationRecord.SignatureData;

            if (context.GetCertificate(signatureData.CertificateId) == null)
            {
                return VerificationResult.Fail;
            }

            return VerificationResult.Ok;
        }
    }
}