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

using System.Collections.Generic;
using System.Text;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Signature
{
    public sealed partial class AggregationHashChain
    {
        /// <summary>
        ///     Aggregation hash chain link TLV element.
        /// </summary>
        public class Link : CompositeTag
        {
            private readonly IntegerTag _levelCorrection;
            private readonly MetaData _metaData;
            private readonly ImprintTag _metaHash;
            private readonly ImprintTag _siblingHash;

            /// <summary>
            /// Create new aggregation hash chain link TLV elment.
            /// </summary>
            /// <param name="direction">Direction</param>
            /// <param name="siblingHash">Sibling hash value</param>
            /// <param name="metadata">Metadata element</param>
            /// <param name="levelCorrection">Level correction</param>
            public Link(LinkDirection direction, DataHash siblingHash, MetaData metadata, ulong levelCorrection)
                : this(new Link(BuildChildTags(siblingHash, metadata, levelCorrection), direction), direction)
            {
            }

            /// <summary>
            /// Create new aggregation hash chain link TLV elment from TLV element.
            /// </summary>
            /// <param name="tag">TLV element</param>
            /// <param name="direction">Direction</param>
            public Link(ITlvTag tag, LinkDirection direction) : base(tag)
            {
                int levelCorrectionCount = 0;
                int siblingHashCount = 0;
                int metaHashCount = 0;
                int metaDataCount = 0;

                for (int i = 0; i < Count; i++)
                {
                    ITlvTag childTag = this[i];

                    switch (childTag.Type)
                    {
                        case Constants.AggregationHashChain.Link.LevelCorrectionTagType:
                            this[i] = _levelCorrection = new IntegerTag(childTag);
                            levelCorrectionCount++;
                            break;
                        case Constants.AggregationHashChain.Link.SiblingHashTagType:
                            this[i] = _siblingHash = new ImprintTag(childTag);
                            siblingHashCount++;
                            break;
                        case Constants.AggregationHashChain.Link.MetaHashTagType:
                            this[i] = _metaHash = new ImprintTag(childTag);
                            metaHashCount++;
                            break;
                        case Constants.AggregationHashChain.MetaData.TagType:
                            this[i] = _metaData = new MetaData(childTag);
                            metaDataCount++;
                            break;
                        default:
                            VerifyUnknownTag(childTag);
                            break;
                    }
                }

                if (levelCorrectionCount > 1)
                {
                    throw new TlvException("Only one levelcorrection value is allowed in aggregation hash chain link.");
                }

                if (!Util.IsOneValueEqualTo(1, siblingHashCount, metaHashCount, metaDataCount))
                {
                    throw new TlvException("Exactly one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link.");
                }

                Direction = direction;
            }

            private Link(ITlvTag[] value, LinkDirection direction) : base((uint)direction, false, false, value)
            {
            }

            /// <summary>
            /// Create child TLV element list
            /// </summary>
            /// <param name="siblingHash">Sibling hash value</param>
            /// <param name="metadata">Metadata element</param>
            /// <param name="levelCorrection">Level correction</param>
            private static ITlvTag[] BuildChildTags(DataHash siblingHash, MetaData metadata, ulong levelCorrection)
            {
                List<ITlvTag> list = new List<ITlvTag>();

                if (siblingHash != null)
                {
                    list.Add(new ImprintTag(Constants.AggregationHashChain.Link.SiblingHashTagType, false, false, siblingHash));
                }

                if (metadata != null)
                {
                    list.Add(metadata);
                }

                if (levelCorrection > 0)
                {
                    list.Add(new IntegerTag(Constants.AggregationHashChain.Link.LevelCorrectionTagType, false, false, levelCorrection));
                }

                return list.ToArray();
            }

            /// <summary>
            ///     Get level correction
            /// </summary>
            public ulong LevelCorrection => _levelCorrection?.Value ?? 0UL;

            /// <summary>
            ///     Get direction
            /// </summary>
            public LinkDirection Direction { get; }

            /// <summary>
            /// Get link identity
            /// </summary>
            /// <returns></returns>
            public string GetIdentity()
            {
                if (_metaHash != null)
                {
                    return CalculateIdentityFromMetaHash();
                }

                return _metaData != null ? _metaData.ClientId : "";
            }

            /// <summary>
            /// Calculate indentity value from meta hash
            /// </summary>
            /// <returns></returns>
            private string CalculateIdentityFromMetaHash()
            {
                byte[] bytes = _metaHash.Value.Imprint;

                if (bytes.Length < 3)
                {
                    Logger.Warn("Meta hash byte array too short. Length: {0}", bytes.Length);
                    return "";
                }

                int length = (bytes[1] << 8) + bytes[2];
                return Encoding.UTF8.GetString(bytes, 3, length);
            }

            /// <summary>
            ///     Get sibling data
            /// </summary>
            public byte[] GetSiblingData()
            {
                if (_siblingHash != null)
                {
                    return _siblingHash.EncodeValue();
                }

                return _metaHash != null ? _metaHash.EncodeValue() : _metaData?.EncodeValue();
            }

            /// <summary>
            /// Returns location pointer based on aggregation hash chain links
            /// </summary>
            /// <param name="links">Aggregation hash chain links</param>
            /// <returns></returns>
            public static ulong GetLocationPointer(Link[] links)
            {
                ulong result = 1;

                for (int i = links.Length - 1; i >= 0; i--)
                {
                    result <<= 1;
                    Link link = links[i];
                    if (link.Direction != LinkDirection.Right)
                    {
                        result++;
                    }
                }

                return result;
            }
        }
    }
}