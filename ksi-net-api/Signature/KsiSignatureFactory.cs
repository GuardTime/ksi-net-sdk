/*
 * Copyright 2013-2016 Guardtime, Inc.
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
using System.Collections.Generic;
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using NLog;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    /// KSI signature factory
    /// </summary>
    public class KsiSignatureFactory : IKsiSignatureFactory
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        private readonly VerificationPolicy _verificationPolicy;
        private readonly IVerificationContext _verificationContext;

        /// <summary>
        /// Indicates if automatic verification should be disabled
        /// </summary>
        public bool DisableVerification { get; set; }

        /// <summary>
        ///     Create KSI signature factory
        /// </summary>
        /// <param name="verificationPolicy">Verification policy to be used when verifying a signature after it is created</param>
        /// <param name="verificationContext">Verification context to be used when verifying a signature after it is created</param>
        public KsiSignatureFactory(VerificationPolicy verificationPolicy = null, IVerificationContext verificationContext = null)
        {
            _verificationPolicy = verificationPolicy ?? new InternalVerificationPolicy();
            _verificationContext = verificationContext ?? new VerificationContext();
        }

        /// <summary>
        ///     Get KSI signature instance from byte array.
        /// </summary>
        /// <param name="bytes">signature byte array</param>
        /// <param name="hash">Signed hash</param>
        /// <param name="level">Signed hash node level value in the aggregation tree</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature Create(byte[] bytes, DataHash hash = null, uint level = 0)
        {
            using (TlvReader reader = new TlvReader(new MemoryStream(bytes)))
            {
                KsiSignature signature = new KsiSignature(reader.ReadTag());

                if (!DisableVerification)
                {
                    Verify(signature, hash, level);
                }

                return signature;
            }
        }

        /// <summary>
        ///     Get KSI signature instance from byte array.
        /// </summary>
        /// <param name="contentBytes">signature content byte array</param>
        /// <param name="hash">Signed hash</param>
        /// <param name="level">Signed hash node level value in the aggregation tree</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature CreateByContent(byte[] contentBytes, DataHash hash = null, uint level = 0)
        {
            KsiSignature signature = new KsiSignature(new RawTag(Constants.KsiSignature.TagType, false, false, contentBytes));

            if (!DisableVerification)
            {
                Verify(signature, hash, level);
            }

            return signature;
        }

        /// <summary>
        ///     Get KSI signature instance from stream.
        /// </summary>
        /// <param name="stream">signature data stream</param>
        /// <param name="hash">Signed hash</param>
        /// <param name="level">Signed hash node level value in the aggregation tree</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature Create(Stream stream, DataHash hash = null, uint level = 0)
        {
            if (stream == null)
            {
                throw new KsiException("Invalid input stream: null.");
            }

            using (TlvReader reader = new TlvReader(stream))
            {
                try
                {
                    Logger.Debug("Creating KSI signature from stream.");
                    KsiSignature signature = new KsiSignature(reader.ReadTag());

                    if (!DisableVerification)
                    {
                        Verify(signature, null, level);
                    }

                    Logger.Debug("Creating KSI signature from stream successful.");

                    return signature;
                }
                catch (TlvException e)
                {
                    Logger.Warn("Creating KSI signature from stream failed: {0}", e);
                    throw;
                }
            }
        }

        /// <summary>
        ///     Get KSI signature instance from aggregation response payload.
        /// </summary>
        /// <param name="payload">aggregation response payload</param>
        /// <param name="hash">Signed hash</param>
        /// <param name="level">Signed hash node level value in the aggregation tree</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature Create(AggregationResponsePayload payload, DataHash hash, uint level = 0)
        {
            if (payload == null)
            {
                throw new KsiException("Invalid aggregation response payload: null.");
            }

            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                foreach (ITlvTag childTag in payload)
                {
                    if (childTag.Type > 0x800 && childTag.Type < 0x900)
                    {
                        writer.WriteTag(childTag);
                    }
                }

                try
                {
                    Logger.Debug("Creating KSI signature from aggregation response. (request id: {0})", payload.RequestId);

                    KsiSignature signature = new KsiSignature(new RawTag(Constants.KsiSignature.TagType, false, false, ((MemoryStream)writer.BaseStream).ToArray()));

                    if (!DisableVerification)
                    {
                        Verify(signature, hash, level);
                    }

                    Logger.Debug("Creating KSI signature from aggregation response successful. (request id: {0})", payload.RequestId);
                    return signature;
                }
                catch (TlvException e)
                {
                    Logger.Warn("Creating KSI signature from aggregation response failed: {0} (request id: {1})", e, payload.RequestId);
                    throw;
                }
            }
        }

        /// <summary>
        /// Get KSI signature instance from tlv tags
        /// </summary>
        /// <param name="aggregationHashChains">Aggregation hash chain tlv elements</param>
        /// <param name="calendarHashChain">Calendar hash chain tlv element</param>
        /// <param name="calendarAuthenticationRecord">Calendar authentication record tlv element</param>
        /// <param name="publicationRecord">Publication record tlv element</param>
        /// <param name="rfc3161Record">RFC3161 record tlv element</param>
        /// <param name="hash">Signed hash</param>
        /// <param name="level">Signed hash node level value in the aggregation tree</param>
        /// <returns></returns>
        public IKsiSignature Create(ICollection<AggregationHashChain> aggregationHashChains, CalendarHashChain calendarHashChain,
                                    CalendarAuthenticationRecord calendarAuthenticationRecord, PublicationRecordInSignature publicationRecord,
                                    Rfc3161Record rfc3161Record, DataHash hash, uint level = 0)
        {
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                foreach (AggregationHashChain childTag in aggregationHashChains)
                {
                    writer.WriteTag(childTag);
                }

                if (calendarHashChain != null)
                {
                    writer.WriteTag(calendarHashChain);

                    if (publicationRecord != null)
                    {
                        writer.WriteTag(publicationRecord);
                    }
                    else if (calendarAuthenticationRecord != null)
                    {
                        writer.WriteTag(calendarAuthenticationRecord);
                    }
                }

                if (rfc3161Record != null)
                {
                    writer.WriteTag(rfc3161Record);
                }

                KsiSignature signature = new KsiSignature(new RawTag(Constants.KsiSignature.TagType, false, false, ((MemoryStream)writer.BaseStream).ToArray()));

                if (!DisableVerification)
                {
                    Verify(signature, hash, level);
                }

                return signature;
            }
        }

        /// <summary>
        /// Verify with given verification policy
        /// </summary>
        /// <param name="signature">Signature to be verified</param>
        /// <param name="hash">Signed hash</param>
        /// <param name="level">Signed hash node level value in the aggregation tree</param>
        private void Verify(IKsiSignature signature, DataHash hash, uint level = 0)
        {
            _verificationContext.Signature = signature;
            _verificationContext.DocumentHash = hash;
            _verificationContext.Level = level;
            VerificationResult verificationResult = _verificationPolicy.Verify(_verificationContext);

            if (verificationResult.ResultCode != VerificationResultCode.Ok)
            {
                Logger.Warn("Signature verification failed.{0}Verification policy: {1}{2}Verification error: {3}{4}Verification result: {5}{6}Signature: {7}",
                    Environment.NewLine,
                    _verificationPolicy.GetRuleName(),
                    Environment.NewLine,
                    verificationResult.VerificationError,
                    Environment.NewLine,
                    verificationResult,
                    Environment.NewLine,
                    this);

                throw new KsiSignatureInvalidContentException("Signature verification failed.", signature, verificationResult);
            }
        }
    }
}