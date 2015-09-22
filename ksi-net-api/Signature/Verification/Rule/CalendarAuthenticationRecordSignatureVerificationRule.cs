using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class CalendarAuthenticationRecordSignatureVerificationRule : VerificationRule
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

            X509Certificate2 certificate = context.PublicationsFile.FindCertificateById(signatureData.CertificateId);
            if (certificate == null)
            {
                throw new InvalidOperationException("Invalid certificate: null");
            }

            byte[] signedBytes = calendarAuthenticationRecord.PublicationData.Encode();
            string digestAlgorithm;
            ICryptoSignatureVerifier cryptoSignatureVerifier = CryptoSignatureVerifierFactory.GetCryptoSignatureVerifierByOid(signatureData.SignatureType, out digestAlgorithm);

            Dictionary<string, object> data = new Dictionary<string, object>();
            data.Add("certificate", certificate);
            data.Add("digestAlgorithm", digestAlgorithm);

            cryptoSignatureVerifier.Verify(signedBytes, signatureData.SignatureValue,  data);

            return VerificationResult.Ok;
        }
    }
}