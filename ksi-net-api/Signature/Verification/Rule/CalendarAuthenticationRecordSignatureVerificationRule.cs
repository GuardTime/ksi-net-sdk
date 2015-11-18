using System;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule validates calendar authentication record signature. Signature is made from calendar authentication record
    ///     publication data. X.509 certificate is searched from publications file and when found, it is used to validate PKI
    ///     signature in calendar authentication record.
    /// </summary>
    public sealed class CalendarAuthenticationRecordSignatureVerificationRule : VerificationRule
    {
        /// <see cref="VerificationRule.Verify" />
        /// <exception cref="KsiException">thrown if verification context is missing</exception>
        /// <exception cref="KsiVerificationException">thrown if verification cannot occur</exception>
        public override VerificationResult Verify(IVerificationContext context)
        {
            CalendarAuthenticationRecord calendarAuthenticationRecord = GetCalendarAuthenticationRecord(GetSignature(context));
            SignatureData signatureData = calendarAuthenticationRecord.SignatureData;
            X509Certificate2 certificate = GetPublicationsFile(context).FindCertificateById(signatureData.GetCertificateId());

            if (certificate == null)
            {
                throw new KsiVerificationException("No certificate found in publications file with id: " +Base16.Encode(signatureData.GetCertificateId()) + ".");
            }

            byte[] signedBytes = calendarAuthenticationRecord.PublicationData.Encode();
            ICryptoSignatureVerifier cryptoSignatureVerifier = CryptoSignatureVerifierFactory.GetCryptoSignatureVerifierByOid(signatureData.SignatureType);
            CryptoSignatureVerificationData data = new CryptoSignatureVerificationData(certificate);

            try
            {
                cryptoSignatureVerifier.Verify(signedBytes, signatureData.GetSignatureValue(), data);
            }
            catch (Exception)
            {
                // TODO: Log exception
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Key02);
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}