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
        private readonly IntegerTag _aggregationTime;
        private readonly List<IntegerTag> _chainIndex = new List<IntegerTag>();
        private readonly ImprintTag _inputHash;
        private readonly IntegerTag _signedAttributesAlgorithm;

        private readonly RawTag _signedAttributesPrefix;
        private readonly RawTag _signedAttributesSuffix;
        private readonly IntegerTag _tstInfoAlgorithm;

        private readonly RawTag _tstInfoPrefix;
        private readonly RawTag _tstInfoSuffix;

        /// <summary>
        ///     Create new RFC3161 record TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public Rfc3161Record(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.Rfc3161Record.TagType)
            {
                throw new TlvException("Invalid RFC#3161 record type(" + Type + ").");
            }

            int aggregationTimeCount = 0;
            int inputHashCount = 0;
            int tstInfoPrefixCount = 0;
            int tstInfoSuffixCount = 0;
            int tstInfoAlgorithmCount = 0;
            int signedAttributesPrefixCount = 0;
            int signedAttributesSuffixCount = 0;
            int signedAttributesAlgorithmCount = 0;

            foreach (ITlvTag childTag in this)
            {
                switch (childTag.Type)
                {
                    case Constants.Rfc3161Record.AggregationTimeTagType:
                        _aggregationTime = new IntegerTag(childTag);
                        aggregationTimeCount++;
                        break;
                    case Constants.Rfc3161Record.ChainIndexTagType:
                        IntegerTag chainTag = new IntegerTag(childTag);
                        _chainIndex.Add(chainTag);
                        break;
                    case Constants.Rfc3161Record.InputHashTagType:
                        _inputHash = new ImprintTag(childTag);
                        inputHashCount++;
                        break;
                    case Constants.Rfc3161Record.TstInfoPrefixTagType:
                        _tstInfoPrefix = new RawTag(childTag);
                        tstInfoPrefixCount++;
                        break;
                    case Constants.Rfc3161Record.TstInfoSuffixTagType:
                        _tstInfoSuffix = new RawTag(childTag);
                        tstInfoSuffixCount++;
                        break;
                    case Constants.Rfc3161Record.TstInfoAlgorithmTagType:
                        _tstInfoAlgorithm = new IntegerTag(childTag);
                        tstInfoAlgorithmCount++;
                        break;
                    case Constants.Rfc3161Record.SignedAttributesPrefixTagType:
                        _signedAttributesPrefix = new RawTag(childTag);
                        signedAttributesPrefixCount++;
                        break;
                    case Constants.Rfc3161Record.SignedAttributesSuffixTagType:
                        _signedAttributesSuffix = new RawTag(childTag);
                        signedAttributesSuffixCount++;
                        break;
                    case Constants.Rfc3161Record.SignedAttributesAlgorithmTagType:
                        _signedAttributesAlgorithm = new IntegerTag(childTag);
                        signedAttributesAlgorithmCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (aggregationTimeCount != 1)
            {
                throw new TlvException("Only one aggregation time must exist in RFC#3161 record.");
            }

            if (_chainIndex.Count == 0)
            {
                throw new TlvException("Chain indexes must exist in RFC#3161 record.");
            }

            if (inputHashCount != 1)
            {
                throw new TlvException("Only one input hash must exist in RFC#3161 record.");
            }

            if (tstInfoPrefixCount != 1)
            {
                throw new TlvException("Only one tstInfo prefix must exist in RFC#3161 record.");
            }

            if (tstInfoSuffixCount != 1)
            {
                throw new TlvException("Only one tstInfo suffix must exist in RFC#3161 record.");
            }

            if (tstInfoAlgorithmCount != 1)
            {
                throw new TlvException("Only one tstInfo algorithm must exist in RFC#3161 record.");
            }

            if (signedAttributesPrefixCount != 1)
            {
                throw new TlvException("Only one signed attributes prefix must exist in RFC#3161 record.");
            }

            if (signedAttributesSuffixCount != 1)
            {
                throw new TlvException("Only one signed attributes suffix must exist in RFC#3161 record.");
            }

            if (signedAttributesAlgorithmCount != 1)
            {
                throw new TlvException(
                    "Only one signed attributes algorithm must exist in RFC#3161 record.");
            }
        }

        /// <summary>
        ///     Get aggregation time.
        /// </summary>
        public ulong AggregationTime => _aggregationTime.Value;

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

            IDataHasher hasher = KsiProvider.GetDataHasher(HashAlgorithm.GetById((byte)_tstInfoAlgorithm.Value));
            hasher.AddData(_tstInfoPrefix.Value);
            hasher.AddData(inputHash.Value);
            hasher.AddData(_tstInfoSuffix.Value);

            inputHash = hasher.GetHash();

            hasher = KsiProvider.GetDataHasher(HashAlgorithm.GetById((byte)_signedAttributesAlgorithm.Value));
            hasher.AddData(_signedAttributesPrefix.Value);
            hasher.AddData(inputHash.Value);
            hasher.AddData(_signedAttributesSuffix.Value);

            return hasher.GetHash();
        }
    }
}