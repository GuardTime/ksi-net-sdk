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

            private IntegerTag _levelCorrection;
            private Metadata _metadata;
            private ImprintTag _siblingHash;
            private RawTag _legacyId;
            private string _legacyIdString;

            /// <summary>
            /// Create new aggregation hash chain link TLV element.
            /// </summary>
            /// <param name="direction">Direction</param>
            /// <param name="siblingHash">Sibling hash value</param>
            /// <param name="metadata">Metadata element</param>
            /// <param name="levelCorrection">Level correction</param>
            public Link(LinkDirection direction, DataHash siblingHash, Metadata metadata, ulong levelCorrection)
                : base((uint)direction, false, false, BuildChildTags(siblingHash, metadata, levelCorrection))
            {
            }

            /// <summary>
            /// Create new aggregation hash chain link TLV element from TLV element.
            /// </summary>
            /// <param name="tag">TLV element</param>
            public Link(ITlvTag tag) : base(tag)
            {
            }

            /// <summary>
            /// Create new aggregation hash chain link TLV element.
            /// </summary>
            /// <param name="direction">Direction</param>
            /// <param name="nonCritical">Is TLV element non critical</param>
            /// <param name="forward">Is TLV element forwarded</param>
            /// <param name="childTags">child TLV element list</param>
            public Link(LinkDirection direction, bool nonCritical, bool forward, ITlvTag[] childTags)
                : base((uint)direction, nonCritical, forward, childTags)
            {
            }

            /// <summary>
            /// Check tag type
            /// </summary>
            protected override void CheckTagType()
            {
                CheckTagType((uint)LinkDirection.Right, (uint)LinkDirection.Left);
            }

            /// <summary>
            /// Parse child element
            /// </summary>
            protected override ITlvTag ParseChild(ITlvTag childTag)
            {
                switch (childTag.Type)
                {
                    case Constants.AggregationHashChain.Link.LevelCorrectionTagType:
                        return _levelCorrection = GetIntegerTag(childTag);
                    case Constants.AggregationHashChain.Link.SiblingHashTagType:
                        return _siblingHash = GetImprintTag(childTag);
                    case Constants.AggregationHashChain.Link.LegacyId:
                        _legacyId = GetRawTag(childTag);
                        _legacyIdString = GetLegacyIdString(_legacyId.Value);
                        return _legacyId;
                    case Constants.AggregationHashChain.Metadata.TagType:
                        return _metadata = childTag as Metadata ?? new Metadata(childTag);

                    default:
                        return base.ParseChild(childTag);
                }
            }

            /// <summary>
            /// Validate the tag
            /// </summary>
            protected override void Validate(TagCounter tagCounter)
            {
                base.Validate(tagCounter);

                if (tagCounter[Constants.AggregationHashChain.Link.LevelCorrectionTagType] > 1)
                {
                    throw new TlvException("Only one levelcorrection value is allowed in aggregation hash chain link.");
                }

                if (!Util.IsOneValueEqualTo(1, tagCounter[Constants.AggregationHashChain.Link.SiblingHashTagType], tagCounter[Constants.AggregationHashChain.Link.LegacyId],
                    tagCounter[Constants.AggregationHashChain.Metadata.TagType]))
                {
                    throw new TlvException("Exactly one of three from sibling hash, legacy id or metadata must exist in aggregation hash chain link.");
                }
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
            public LinkDirection Direction => (LinkDirection)Type;

            /// <summary>
            /// Metadata element
            /// </summary>
            public Metadata Metadata => _metadata;

            /// <summary>
            /// Get sibling hash
            /// </summary>
            public DataHash SiblingHash => _siblingHash?.Value;

            /// <summary>
            /// Get link identity
            /// </summary>
            /// <returns></returns>
            public IIdentity GetIdentity()
            {
                if (_legacyId != null)
                {
                    return new LegacyIdentity(_legacyIdString);
                }

                return _metadata;
            }

            private static string GetLegacyIdString(byte[] bytes)
            {
                if (bytes.Length == 0)
                {
                    throw new TlvException("Invalid legacy id tag: empty");
                }

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