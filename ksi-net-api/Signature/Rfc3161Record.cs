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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     RFC3161 record TLV element
    /// </summary>
    public sealed class Rfc3161Record : CompositeTag
    {
        private IntegerTag _aggregationTime;
        private readonly List<IntegerTag> _chainIndex = new List<IntegerTag>();
        private ImprintTag _inputHash;
        private IntegerTag _signedAttributesAlgorithm;

        private RawTag _signedAttributesPrefix;
        private RawTag _signedAttributesSuffix;
        private IntegerTag _tstInfoAlgorithm;

        private RawTag _tstInfoPrefix;
        private RawTag _tstInfoSuffix;

        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.Rfc3161Record.TagType;

        /// <summary>
        ///     Create new RFC3161 record TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public Rfc3161Record(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.Rfc3161Record.AggregationTimeTagType:
                    return _aggregationTime = GetIntegerTag(childTag);
                case Constants.Rfc3161Record.ChainIndexTagType:
                    IntegerTag chainTag = GetIntegerTag(childTag);
                    _chainIndex.Add(chainTag);
                    return chainTag;
                case Constants.Rfc3161Record.InputHashTagType:
                    return _inputHash = GetImprintTag(childTag);

                case Constants.Rfc3161Record.TstInfoPrefixTagType:
                    return _tstInfoPrefix = GetRawTag(childTag);

                case Constants.Rfc3161Record.TstInfoSuffixTagType:
                    return _tstInfoSuffix = GetRawTag(childTag);

                case Constants.Rfc3161Record.TstInfoAlgorithmTagType:
                    return _tstInfoAlgorithm = GetIntegerTag(childTag);

                case Constants.Rfc3161Record.SignedAttributesPrefixTagType:
                    return _signedAttributesPrefix = GetRawTag(childTag);

                case Constants.Rfc3161Record.SignedAttributesSuffixTagType:
                    return _signedAttributesSuffix = GetRawTag(childTag);

                case Constants.Rfc3161Record.SignedAttributesAlgorithmTagType:
                    return _signedAttributesAlgorithm = GetIntegerTag(childTag);
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

            if (tagCounter[Constants.Rfc3161Record.AggregationTimeTagType] != 1)
            {
                throw new TlvException("Exactly one aggregation time must exist in RFC#3161 record.");
            }

            if (_chainIndex.Count == 0)
            {
                throw new TlvException("Chain indexes must exist in RFC#3161 record.");
            }

            if (tagCounter[Constants.Rfc3161Record.InputHashTagType] != 1)
            {
                throw new TlvException("Exactly one input hash must exist in RFC#3161 record.");
            }

            if (tagCounter[Constants.Rfc3161Record.TstInfoPrefixTagType] != 1)
            {
                throw new TlvException("Exactly one tstInfo prefix must exist in RFC#3161 record.");
            }

            if (tagCounter[Constants.Rfc3161Record.TstInfoSuffixTagType] != 1)
            {
                throw new TlvException("Exactly one tstInfo suffix must exist in RFC#3161 record.");
            }

            if (tagCounter[Constants.Rfc3161Record.TstInfoAlgorithmTagType] != 1)
            {
                throw new TlvException("Exactly one tstInfo algorithm must exist in RFC#3161 record.");
            }

            if (tagCounter[Constants.Rfc3161Record.SignedAttributesPrefixTagType] != 1)
            {
                throw new TlvException("Exactly one signed attributes prefix must exist in RFC#3161 record.");
            }

            if (tagCounter[Constants.Rfc3161Record.SignedAttributesSuffixTagType] != 1)
            {
                throw new TlvException("Exactly one signed attributes suffix must exist in RFC#3161 record.");
            }

            if (tagCounter[Constants.Rfc3161Record.SignedAttributesAlgorithmTagType] != 1)
            {
                throw new TlvException("Exactly one signed attributes algorithm must exist in RFC#3161 record.");
            }
        }

        /// <summary>
        ///     Get aggregation time.
        /// </summary>
        public ulong AggregationTime => _aggregationTime.Value;

        /// <summary>
        /// Get chain index values
        /// </summary>
        /// <returns></returns>
        public ulong[] GetChainIndex()
        {
            List<ulong> result = new List<ulong>();
            foreach (IntegerTag tag in _chainIndex)
            {
                result.Add(tag.Value);
            }
            return result.ToArray();
        }

        /// <summary>
        ///     Get RFC3161 input hash
        /// </summary>
        public DataHash InputHash => _inputHash.Value;

        /// <summary>
        ///     Get output hash for RFC 3161 from document hash
        /// </summary>
        /// <param name="inputHash">document hash</param>
        /// <returns>aggregation input hash</returns>
        public DataHash GetOutputHash(DataHash inputHash)
        {
            if (inputHash == null)
            {
                throw new KsiException("Invalid input hash: null.");
            }

            IDataHasher hasher = KsiProvider.CreateDataHasher(HashAlgorithm.GetById((byte)_tstInfoAlgorithm.Value));
            hasher.AddData(_tstInfoPrefix.Value);
            hasher.AddData(inputHash.Value);
            hasher.AddData(_tstInfoSuffix.Value);

            inputHash = hasher.GetHash();

            hasher = KsiProvider.CreateDataHasher(HashAlgorithm.GetById((byte)_signedAttributesAlgorithm.Value));
            hasher.AddData(_signedAttributesPrefix.Value);
            hasher.AddData(inputHash.Value);
            hasher.AddData(_signedAttributesSuffix.Value);

            return hasher.GetHash();
        }
    }
}