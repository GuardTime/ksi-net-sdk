using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;

namespace Guardtime.KSI.Signature.Verification.Rule.Pki
{
    public sealed class CalendarAuthenticationRecordSignatureVerificationRule : IRule
    {
        public override VerificationResult Verify(VerificationContext context)
        {
            CalendarAuthenticationRecord calendarAuthenticationRecord = context.CalendarAuthenticationRecord;
            if (calendarAuthenticationRecord == null)
            {
                throw new InvalidOperationException("Invalid calendar authentication record: null");
            }

            SignatureData signatureData = calendarAuthenticationRecord.SignatureData;
            X509Certificate2 certificate = context.GetCertificate(signatureData.CertificateId);
            if (certificate == null)
            {
                throw new InvalidOperationException("Invalid certificate: null");
            }

            byte[] signedBytes = calendarAuthenticationRecord.PublicationData.Encode();
            string digestAlgorithm;
            ICryptoSignatureVerifier cryptoSignatureVerifier = CryptoSignatureVerifierFactory.GetCryptoSignatureVerificationByOid(signatureData.SignatureType, out digestAlgorithm);

            Dictionary<string, object> data = new Dictionary<string, object>();
            data.Add("certificate", certificate);
            data.Add("digestAlgorithm", digestAlgorithm);

            cryptoSignatureVerifier.Verify(signedBytes, signatureData.SignatureValue,  data);

            return VerificationResult.Ok;
        }
    }
}