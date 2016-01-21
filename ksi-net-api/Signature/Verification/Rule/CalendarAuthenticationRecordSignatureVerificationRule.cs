using System;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;
using NLog;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule validates calendar authentication record signature. Signature is made from calendar authentication record
    ///     publication data. X.509 certificate is searched from publications file and when found, it is used to validate PKI
    ///     signature in calendar authentication record.
    /// </summary>
    public sealed class CalendarAuthenticationRecordSignatureVerificationRule : VerificationRule
    {
        private readonly X509Store _trustStore;
        private readonly ICertificateSubjectRdnSelector _certificateRdnSelector;

        /// <summary>
        /// Create calendar authentication record signature verification rule.
        /// </summary>
        /// <param name="trustStore">trust store</param>
        /// <param name="certificateRdnSelector">certificate rdn selector</param>
        public CalendarAuthenticationRecordSignatureVerificationRule(X509Store trustStore, ICertificateSubjectRdnSelector certificateRdnSelector)
        {
            if (certificateRdnSelector == null)
            {
                throw new ArgumentNullException(nameof(certificateRdnSelector));
            }

            _trustStore = trustStore;
            _certificateRdnSelector = certificateRdnSelector;
        }

        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            CalendarAuthenticationRecord calendarAuthenticationRecord = GetCalendarAuthenticationRecord(GetSignature(context));
            SignatureData signatureData = calendarAuthenticationRecord.SignatureData;
            byte[] certificateBytes = GetPublicationsFile(context).FindCertificateById(signatureData.GetCertificateId());

            if (certificateBytes == null)
            {
                throw new KsiVerificationException("No certificate found in publications file with id: " + Base16.Encode(signatureData.GetCertificateId()) + ".");
            }

            byte[] signedBytes = calendarAuthenticationRecord.PublicationData.Encode();
            ICryptoSignatureVerifier cryptoSignatureVerifier = CryptoSignatureVerifierFactory.GetCryptoSignatureVerifierByOid(signatureData.SignatureType, _trustStore,
                _certificateRdnSelector);
            CryptoSignatureVerificationData data = new CryptoSignatureVerificationData(certificateBytes);

            try
            {
                cryptoSignatureVerifier.Verify(signedBytes, signatureData.GetSignatureValue(), data);
            }
            catch (PkiVerificationFailedException)
            {
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Key02);
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}