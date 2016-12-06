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
        ///     Create new RFC3161 record TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public Rfc3161Record(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Validate the tag
        /// </summary>
        protected override void Validate()
        {
            CheckTagType(Constants.Rfc3161Record.TagType);

            base.Validate();

            int aggregationTimeCount = 0;
            int inputHashCount = 0;
            int tstInfoPrefixCount = 0;
            int tstInfoSuffixCount = 0;
            int tstInfoAlgorithmCount = 0;
            int signedAttributesPrefixCount = 0;
            int signedAttributesSuffixCount = 0;
            int signedAttributesAlgorithmCount = 0;

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.Rfc3161Record.AggregationTimeTagType:
                        this[i] = _aggregationTime = new IntegerTag(childTag);
                        aggregationTimeCount++;
                        break;
                    case Constants.Rfc3161Record.ChainIndexTagType:
                        IntegerTag chainTag = new IntegerTag(childTag);
                        _chainIndex.Add(chainTag);
                        this[i] = chainTag;
                        break;
                    case Constants.Rfc3161Record.InputHashTagType:
                        this[i] = _inputHash = new ImprintTag(childTag);
                        inputHashCount++;
                        break;
                    case Constants.Rfc3161Record.TstInfoPrefixTagType:
                        this[i] = _tstInfoPrefix = new RawTag(childTag);
                        tstInfoPrefixCount++;
                        break;
                    case Constants.Rfc3161Record.TstInfoSuffixTagType:
                        this[i] = _tstInfoSuffix = new RawTag(childTag);
                        tstInfoSuffixCount++;
                        break;
                    case Constants.Rfc3161Record.TstInfoAlgorithmTagType:
                        this[i] = _tstInfoAlgorithm = new IntegerTag(childTag);
                        tstInfoAlgorithmCount++;
                        break;
                    case Constants.Rfc3161Record.SignedAttributesPrefixTagType:
                        this[i] = _signedAttributesPrefix = new RawTag(childTag);
                        signedAttributesPrefixCount++;
                        break;
                    case Constants.Rfc3161Record.SignedAttributesSuffixTagType:
                        this[i] = _signedAttributesSuffix = new RawTag(childTag);
                        signedAttributesSuffixCount++;
                        break;
                    case Constants.Rfc3161Record.SignedAttributesAlgorithmTagType:
                        this[i] = _signedAttributesAlgorithm = new IntegerTag(childTag);
                        signedAttributesAlgorithmCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (aggregationTimeCount != 1)
            {
                throw new TlvException("Exactly one aggregation time must exist in RFC#3161 record.");
            }

            if (_chainIndex.Count == 0)
            {
                throw new TlvException("Chain indexes must exist in RFC#3161 record.");
            }

            if (inputHashCount != 1)
            {
                throw new TlvException("Exactly one input hash must exist in RFC#3161 record.");
            }

            if (tstInfoPrefixCount != 1)
            {
                throw new TlvException("Exactly one tstInfo prefix must exist in RFC#3161 record.");
            }

            if (tstInfoSuffixCount != 1)
            {
                throw new TlvException("Exactly one tstInfo suffix must exist in RFC#3161 record.");
            }

            if (tstInfoAlgorithmCount != 1)
            {
                throw new TlvException("Exactly one tstInfo algorithm must exist in RFC#3161 record.");
            }

            if (signedAttributesPrefixCount != 1)
            {
                throw new TlvException("Exactly one signed attributes prefix must exist in RFC#3161 record.");
            }

            if (signedAttributesSuffixCount != 1)
            {
                throw new TlvException("Exactly one signed attributes suffix must exist in RFC#3161 record.");
            }

            if (signedAttributesAlgorithmCount != 1)
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