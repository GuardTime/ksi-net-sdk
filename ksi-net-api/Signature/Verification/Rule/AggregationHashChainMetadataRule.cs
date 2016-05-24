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

using System.Collections.ObjectModel;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;
using NLog;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    /// <summary>
    ///     Rule verifies if all metadata tags in aggregation hash chains are valid.
    /// </summary>
    public sealed class AggregationHashChainMetadataRule : VerificationRule
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        /// <see cref="VerificationRule.Verify" />
        public override VerificationResult Verify(IVerificationContext context)
        {
            ReadOnlyCollection<AggregationHashChain> aggregationHashChains = GetAggregationHashChains(GetSignature(context), true);

            foreach (AggregationHashChain aggregationHashChain in aggregationHashChains)
            {
                foreach (AggregationHashChain.Link link in aggregationHashChain.GetChainLinks())
                {
                    if (link.Metadata == null)
                    {
                        continue;
                    }

                    RawTag paddingTag = link.Metadata.Padding;

                    if (paddingTag != null)
                    {
                        bool isValid = true;
                        string message = null;

                        if (link.Metadata.PaddingTagIndex != 0)
                        {
                            isValid = false;
                            message = "Padding is not the first element.";
                        }

                        if (isValid && link.Metadata.Padding.IsReadAsTlv16 != false)
                        {
                            isValid = false;
                            message = "Padding is not tlv8.";
                        }

                        if (isValid && (!paddingTag.NonCritical || !paddingTag.Forward))
                        {
                            isValid = false;
                            message = "Non-critical and forward flags must be set.";
                        }

                        if (isValid && !Util.IsArrayEqual(paddingTag.Value, new byte[] { 0x1 }) && !Util.IsArrayEqual(paddingTag.Value, new byte[] { 0x1, 0x1 }))
                        {
                            isValid = false;
                            message = "Unknown padding value.";
                        }

                        if (isValid && Util.GetTlvLength(link.Metadata) % 2 != 0)
                        {
                            isValid = false;
                            message = "Invalid padding value.";
                        }

                        if (!isValid)
                        {
                            Logger.Warn("Metadata with padding may not be trusted. " + message + " Metadata: " + link.Metadata);
                            return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int11);
                        }
                    }
                    else
                    {
                        byte[] metadata = link.Metadata.EncodeValue();

                        if (metadata.Length == 0)
                        {
                            continue;
                        }

                        byte hashAlgorithmId = metadata[0];

                        if (HashAlgorithm.IsInvalidAlgorithm(hashAlgorithmId))
                        {
                            continue;
                        }

                        HashAlgorithm hashAlgorithm = HashAlgorithm.GetById(hashAlgorithmId);

                        if (hashAlgorithm != null && hashAlgorithm.Length == metadata.Length - 1)
                        {
                            Logger.Warn("Metadata without padding may not be trusted. Metadata: " + link.Metadata);
                            return new VerificationResult(GetRuleName(), VerificationResultCode.Fail, VerificationError.Int11);
                        }
                    }
                }
            }

            return new VerificationResult(GetRuleName(), VerificationResultCode.Ok);
        }
    }
}