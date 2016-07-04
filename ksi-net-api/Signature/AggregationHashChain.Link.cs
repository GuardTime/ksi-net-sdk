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
            private const byte LegacyIdFirstOctet = 0x3;
            private const byte LegacyIdLength = 29;

            private readonly IntegerTag _levelCorrection;
            private readonly Metadata _metadata;
            private readonly ImprintTag _siblingHash;
            private readonly RawTag _legacyId;
            private readonly string _legacyIdString;

            /// <summary>
            /// Create new aggregation hash chain link TLV element.
            /// </summary>
            /// <param name="direction">Direction</param>
            /// <param name="siblingHash">Sibling hash value</param>
            /// <param name="metadata">Metadata element</param>
            /// <param name="levelCorrection">Level correction</param>
            public Link(LinkDirection direction, DataHash siblingHash, Metadata metadata, ulong levelCorrection)
                : this(new Link(BuildChildTags(siblingHash, metadata, levelCorrection), direction), direction)
            {
            }

            /// <summary>
            /// Create new aggregation hash chain link TLV element from TLV element.
            /// </summary>
            /// <param name="tag">TLV element</param>
            /// <param name="direction">Direction</param>
            public Link(ITlvTag tag, LinkDirection direction) : base(tag)
            {
                int levelCorrectionCount = 0;
                int siblingHashCount = 0;
                int legacyIdCount = 0;
                int metadataCount = 0;

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
                        case Constants.AggregationHashChain.Link.LegacyId:
                            this[i] = _legacyId = new RawTag(childTag);
                            _legacyIdString = GetLegacyIdString(_legacyId.Value);
                            legacyIdCount++;
                            break;
                        case Constants.AggregationHashChain.Metadata.TagType:
                            this[i] = _metadata = childTag as Metadata ?? new Metadata(childTag);
                            metadataCount++;
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

                if (!Util.IsOneValueEqualTo(1, siblingHashCount, legacyIdCount, metadataCount))
                {
                    throw new TlvException("Exactly one of three from sibling hash, legacy id or metadata must exist in aggregation hash chain link.");
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
            private static ITlvTag[] BuildChildTags(DataHash siblingHash, Metadata metadata, ulong levelCorrection)
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
            /// Metadata element
            /// </summary>
            public Metadata Metadata => _metadata;

            /// <summary>
            /// Get link identity
            /// </summary>
            /// <returns></returns>
            public string GetIdentity()
            {
                if (_legacyId != null)
                {
                    return _legacyIdString;
                }

                return _metadata != null ? _metadata.ClientId : "";
            }

            private static string GetLegacyIdString(byte[] bytes)
            {
                if (bytes[0] != LegacyIdFirstOctet)
                {
                    throw new TlvException("Invalid first octet in legacy id tag: " + bytes[0]);
                }

                if (bytes[1] != 0x0)
                {
                    throw new TlvException("Invalid second octet in legacy id tag: " + bytes[0]);
                }

                if (bytes.Length != LegacyIdLength)
                {
                    throw new TlvException("Invalid legacy id tag length. Length: " + bytes.Length);
                }

                int idStringLength = bytes[2];

                if (bytes.Length < 4 + idStringLength)
                {
                    throw new TlvException("Invalid legacy id length value: " + idStringLength);
                }

                for (int i = idStringLength + 3; i < bytes.Length; i++)
                {
                    if (bytes[i] != 0x0)
                    {
                        throw new TlvException("Invalid padding octet. Index: " + i);
                    }
                }

                return new UTF8Encoding(false, true).GetString(bytes, 3, idStringLength);
            }

            /// <summary>
            ///     Get data byte array
            /// </summary>
            public byte[] GetSiblingData()
            {
                if (_siblingHash != null)
                {
                    return _siblingHash.EncodeValue();
                }

                return _legacyId != null ? _legacyId.EncodeValue() : _metadata?.EncodeValue();
            }
        }
    }
}