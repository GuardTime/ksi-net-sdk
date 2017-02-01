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
            using (Stream stream = new MemoryStream(bytes))
            {
                return Create(stream, hash, level);
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
            return CreateAndVerify(new RawTag(Constants.KsiSignature.TagType, false, false, contentBytes), hash, level);
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
                    IKsiSignature signature = CreateAndVerify(reader.ReadTag(), null, level);
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
            return CreateFromResponsePayload(payload, payload.RequestId, hash, level);
        }

        /// <summary>
        ///     Get KSI signature instance from legacy aggregation response payload.
        /// </summary>
        /// <param name="payload">aggregation response payload</param>
        /// <param name="hash">Signed hash</param>
        /// <param name="level">Signed hash node level value in the aggregation tree</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature Create(LegacyAggregationResponsePayload payload, DataHash hash, uint level = 0)
        {
            if (payload == null)
            {
                throw new KsiException("Invalid aggregation response payload: null.");
            }
            return CreateFromResponsePayload(payload, payload.RequestId, hash, level);
        }

        private IKsiSignature CreateFromResponsePayload(CompositeTag payload, ulong requestId, DataHash hash, uint level)
        {
            List<ITlvTag> childTags = new List<ITlvTag>();

            foreach (ITlvTag childTag in payload)
            {
                if (childTag.Type > 0x800 && childTag.Type < 0x900)
                {
                    childTags.Add(childTag);
                }
            }

            try
            {
                Logger.Debug("Creating KSI signature from aggregation response. (request id: {0})", requestId);

                IKsiSignature signature = CreateAndVerify(childTags.ToArray(), hash, level);

                Logger.Debug("Creating KSI signature from aggregation response successful. (request id: {0})", requestId);
                return signature;
            }
            catch (TlvException e)
            {
                Logger.Warn("Creating KSI signature from aggregation response failed: {0} (request id: {1})", e, requestId);
                throw;
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
            List<ITlvTag> childTags = new List<ITlvTag>();

            foreach (AggregationHashChain childTag in aggregationHashChains)
            {
                childTags.Add(childTag);
            }

            if (calendarHashChain != null)
            {
                childTags.Add(calendarHashChain);

                if (publicationRecord != null)
                {
                    childTags.Add(publicationRecord);
                }
                else if (calendarAuthenticationRecord != null)
                {
                    childTags.Add(calendarAuthenticationRecord);
                }
            }

            if (rfc3161Record != null)
            {
                childTags.Add(rfc3161Record);
            }

            return CreateAndVerify(childTags.ToArray(), hash, level);
        }

        /// <summary>
        /// Create signature and verify with given verification policy
        /// </summary>
        /// <param name="signatureRaw">KSI signature</param>
        /// <param name="hash">Signed hash</param>
        /// <param name="level">Signed hash node level value in the aggregation tree</param>
        private IKsiSignature CreateAndVerify(RawTag signatureRaw, DataHash hash, uint level = 0)
        {
            KsiSignature signature = new KsiSignature(signatureRaw);

            if (level > 0)
            {
                signature = new KsiSignature(false, false, signature.GetChildren(), level);
            }

            Verify(signature, hash);
            return signature;
        }

        /// <summary>
        /// Create signature and verify with given verification policy
        /// </summary>
        /// <param name="childTags">Child tags</param>
        /// <param name="hash">Signed hash</param>
        /// <param name="level">Signed hash node level value in the aggregation tree</param>
        private IKsiSignature CreateAndVerify(ITlvTag[] childTags, DataHash hash, uint level = 0)
        {
            KsiSignature signature = level > 0 ? new KsiSignature(false, false, childTags, level) : new KsiSignature(false, false, childTags);

            Verify(signature, hash);
            return signature;
        }

        /// <summary>
        /// Verify signature with given verification policy
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="hash">Signed hash</param>
        private void Verify(IKsiSignature signature, DataHash hash)
        {
            _verificationContext.Signature = signature;
            _verificationContext.DocumentHash = hash;
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