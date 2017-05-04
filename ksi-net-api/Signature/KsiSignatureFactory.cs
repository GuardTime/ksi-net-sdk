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
using System.Collections.Generic;
using System.Collections.ObjectModel;
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
        /// <returns>KSI signature</returns>
        public IKsiSignature Create(byte[] bytes, DataHash hash = null)
        {
            using (Stream stream = new MemoryStream(bytes))
            {
                return Create(stream, hash);
            }
        }

        /// <summary>
        ///     Get KSI signature instance from byte array.
        /// </summary>
        /// <param name="contentBytes">signature content byte array</param>
        /// <param name="hash">Signed hash</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature CreateByContent(byte[] contentBytes, DataHash hash = null)
        {
            return CreateAndVerify(new RawTag(Constants.KsiSignature.TagType, false, false, contentBytes), hash);
        }

        /// <summary>
        ///     Get KSI signature instance from stream.
        /// </summary>
        /// <param name="stream">signature data stream</param>
        /// <param name="hash">Signed hash</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature Create(Stream stream, DataHash hash = null)
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
                    IKsiSignature signature = CreateAndVerify(reader.ReadTag(), null);
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
        public IKsiSignature Create(AggregationResponsePayload payload, DataHash hash, uint? level = null)
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
        public IKsiSignature Create(LegacyAggregationResponsePayload payload, DataHash hash, uint? level = null)
        {
            if (payload == null)
            {
                throw new KsiException("Invalid aggregation response payload: null.");
            }
            return CreateFromResponsePayload(payload, payload.RequestId, hash, level);
        }

        private IKsiSignature CreateFromResponsePayload(RequestResponsePayload payload, ulong requestId, DataHash hash, uint? level)
        {
            try
            {
                Logger.Debug("Creating KSI signature from aggregation response. (request id: {0})", requestId);

                KsiSignature signature = new KsiSignature(false, false, payload.GetSignatureChildTags());

                if (level > 0)
                {
                    signature = GetSignatureWithLevelCorrection(signature, level.Value);
                }

                Verify(signature, hash);

                Logger.Debug("Creating KSI signature from aggregation response successful. (request id: {0})", requestId);
                return signature;
            }
            catch (TlvException e)
            {
                Logger.Warn("Creating KSI signature from aggregation response failed: {0} (request id: {1})", e, requestId);
                throw;
            }
        }

        private static KsiSignature GetSignatureWithLevelCorrection(KsiSignature signature, uint fistLinkLevelCorrection)
        {
            ReadOnlyCollection<AggregationHashChain> aggregationHashChains = signature.GetAggregationHashChains();

            if (aggregationHashChains.Count > 0)
            {
                TlvTagBuilder builder = new TlvTagBuilder(signature);
                AggregationHashChain firstAggregationHashChain = aggregationHashChains[0];
                builder.ReplaceChildTag(firstAggregationHashChain, GetAggregationHashChainWithLevelCorrection(firstAggregationHashChain, fistLinkLevelCorrection));
                return new KsiSignature(false, false, builder.GetChildTags());
            }

            return signature;
        }

        private static AggregationHashChain GetAggregationHashChainWithLevelCorrection(AggregationHashChain aggregationHashChain, uint levelCorrection)
        {
            ReadOnlyCollection<AggregationHashChain.Link> chainLinks = aggregationHashChain.GetChainLinks();

            if (chainLinks.Count > 0)
            {
                TlvTagBuilder builder = new TlvTagBuilder(aggregationHashChain);
                AggregationHashChain.Link firstLink = chainLinks[0];
                builder.ReplaceChildTag(firstLink, GetLinkWithLevelCorrection(firstLink, levelCorrection));
                return new AggregationHashChain(builder.BuildTag());
            }

            return aggregationHashChain;
        }

        private static AggregationHashChain.Link GetLinkWithLevelCorrection(AggregationHashChain.Link link, uint levelCorrection)
        {
            TlvTagBuilder builder = new TlvTagBuilder(link);
            IntegerTag levelCorrectionTag = builder.GetChildByType(Constants.AggregationHashChain.Link.LevelCorrectionTagType) as IntegerTag;

            if (levelCorrectionTag != null)
            {
                IntegerTag newLevelCorrectionTag = new IntegerTag(
                    levelCorrectionTag.Type,
                    levelCorrectionTag.NonCritical,
                    levelCorrectionTag.Forward,
                    levelCorrectionTag.Value + levelCorrection);

                builder.ReplaceChildTag(levelCorrectionTag, newLevelCorrectionTag);
            }
            else
            {
                builder.AddChildTag(new IntegerTag(Constants.AggregationHashChain.Link.LevelCorrectionTagType, false, false, levelCorrection));
            }

            return new AggregationHashChain.Link(builder.BuildTag());
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
        /// <returns></returns>
        public IKsiSignature Create(ICollection<AggregationHashChain> aggregationHashChains, CalendarHashChain calendarHashChain,
                                    CalendarAuthenticationRecord calendarAuthenticationRecord, PublicationRecordInSignature publicationRecord,
                                    Rfc3161Record rfc3161Record, DataHash hash)
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

            return CreateAndVerify(childTags.ToArray(), hash);
        }

        /// <summary>
        /// Create signature and verify with given verification policy
        /// </summary>
        /// <param name="signatureRaw">KSI signature</param>
        /// <param name="hash">Signed hash</param>
        private IKsiSignature CreateAndVerify(RawTag signatureRaw, DataHash hash)
        {
            KsiSignature signature = new KsiSignature(signatureRaw);

            Verify(signature, hash);
            return signature;
        }

        /// <summary>
        /// Create signature and verify with given verification policy
        /// </summary>
        /// <param name="childTags">Child tags</param>
        /// <param name="hash">Signed hash</param>
        private IKsiSignature CreateAndVerify(ITlvTag[] childTags, DataHash hash)
        {
            KsiSignature signature = new KsiSignature(false, false, childTags);

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
                Logger.Warn("Signature verification failed.{0}Verification policy: {1}{0}Verification error: {2}{0}Verification result: {3}{0}Signature: {4}",
                    Environment.NewLine,
                    _verificationPolicy.GetRuleName(),
                    verificationResult.VerificationError,
                    verificationResult,
                    signature);

                throw new KsiSignatureInvalidContentException("Signature verification failed.", signature, verificationResult);
            }
        }
    }
}