using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    public sealed class CalendarAuthenticationRecordSignatureVerificationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="ArgumentNullException">thrown if context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (context.Signature == null)
            {
                throw new KsiVerificationException("Invalid KSI signature: null");
            }

            if (context.PublicationsFile == null)
            {
                throw new KsiVerificationException("Invalid publications file: null");
            }

            CalendarAuthenticationRecord calendarAuthenticationRecord = context.Signature.CalendarAuthenticationRecord;
            if (calendarAuthenticationRecord == null)
            {
                throw new KsiVerificationException("Invalid calendar authentication record in signature: null");
            }

            SignatureData signatureData = calendarAuthenticationRecord.SignatureData;
            X509Certificate2 certificate = context.PublicationsFile.FindCertificateById(signatureData.CertificateId);
            if (certificate == null)
            {
                throw new KsiVerificationException("No certificate found in publications file with id: " +
                                                   Base16.Encode(signatureData.CertificateId));
            }

            byte[] signedBytes = calendarAuthenticationRecord.PublicationData.Encode();
            string digestAlgorithm;
            ICryptoSignatureVerifier cryptoSignatureVerifier =
                CryptoSignatureVerifierFactory.GetCryptoSignatureVerifierByOid(signatureData.SignatureType,
                    out digestAlgorithm);

            Dictionary<string, object> data = new Dictionary<string, object>();
            data.Add("certificate", certificate);
            data.Add("digestAlgorithm", digestAlgorithm);

            try
            {
                cryptoSignatureVerifier.Verify(signedBytes, signatureData.SignatureValue, data);
            }
            catch (Exception e)
            {
                // TODO: Catch only crypto exception
                // TODO: Log exception
                return VerificationResult.Fail;
            }


            return VerificationResult.Ok;
        }
    }
}