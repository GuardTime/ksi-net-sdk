/*
 * Copyright 2013-2017 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

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
        /// <summary>
        /// Create calendar authentication record signature verification rule.
        /// </summary>
        public CalendarAuthenticationRecordSignatureVerificationRule()
        {
        }

        /// <summary>
        /// Create calendar authentication record signature verification rule.
        /// </summary>
        [Obsolete("Use CalendarAuthenticationRecordSignatureVerificationRule() instead.")]
        public CalendarAuthenticationRecordSignatureVerificationRule(X509Store trustStore, ICertificateSubjectRdnSelector certificateRdnSelector)
        {
        }

        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            IKsiSignature signature = GetSignature(context);
            CalendarAuthenticationRecord calendarAuthenticationRecord = GetCalendarAuthenticationRecord(signature);
            SignatureData signatureData = calendarAuthenticationRecord.SignatureData;
            byte[] certificateBytes = GetPublicationsFile(context).FindCertificateById(signatureData.GetCertificateId());

            if (certificateBytes == null)
            {
                throw new KsiVerificationException("No certificate found in publications file with id: " + Base16.Encode(signatureData.GetCertificateId()) + ".");
            }

            byte[] signedBytes = calendarAuthenticationRecord.PublicationData.Encode();

            try
            {
                ICryptoSignatureVerifier cryptoSignatureVerifier = CryptoSignatureVerifierFactory.GetCryptoSignatureVerifierByOid(signatureData.SignatureType);
                CryptoSignatureVerificationData data = new CryptoSignatureVerificationData(certificateBytes, signature.AggregationTime);
                cryptoSignatureVerifier.Verify(signedBytes, signatureData.GetSignatureValue(), data);
            }
            catch (PkiVerificationFailedCertNotValidException ex)
            {
                Logger.Debug(ex);
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Key03);
            }
            catch (PkiVerificationFailedException ex)
            {
                Logger.Debug("Could not verify signature.{0}Signature type: {1}{0}{2}{0}{3}",
                    Environment.NewLine,
                    signatureData.SignatureType,
                    ex,
                    ex.AdditionalInfo);
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Key02);
            }
            catch (PkiVerificationErrorException ex)
            {
                Logger.Debug("Signature verification error.{0}Signature type: {1}{0}{2}",
                    Environment.NewLine,
                    signatureData.SignatureType,
                    ex);
                return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Key02);
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}