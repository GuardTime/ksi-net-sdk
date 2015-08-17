using System.Collections.Generic;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using System;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    /// RFC3161 record TLV element
    /// </summary>
    public class Rfc3161Record : CompositeTag
    {
        // TODO: Better name
        /// <summary>
        /// RFC3161 record tag type
        /// </summary>
        public const uint TagType = 0x806;
        private const uint AggregationTimeTagType = 0x2;
        private const uint ChainIndexTagType = 0x3;
        private const uint InputHashTagType = 0x5;
        private const uint TstInfoPrefixTagType = 0x10;
        private const uint TstInfoSuffixTagType = 0x11;
        private const uint TstInfoAlgorithmTagType = 0x12;
        private const uint SignedAttributesPrefixTagType = 0x13;
        private const uint SignedAttributesSuffixTagType = 0x14;
        private const uint SignedAttributesAlgorithmTagType = 0x15;

        private readonly IntegerTag _aggregationTime;
        private readonly List<IntegerTag> _chainIndex = new List<IntegerTag>();
        private readonly ImprintTag _inputHash;

        private readonly RawTag _tstInfoPrefix;
        private readonly RawTag _tstInfoSuffix;
        private readonly IntegerTag _tstInfoAlgorithm;

        private readonly RawTag _signedAttributesPrefix;
        private readonly RawTag _signedAttributesSuffix;
        private readonly IntegerTag _signedAttributesAlgorithm;

        /// <summary>
        /// Get RFC3161 input hash
        /// </summary>
        public DataHash InputHash
        {
            get
            {
                return _inputHash.Value;
            }
        }

        /// <summary>
        /// Create new RFC3161 record TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public Rfc3161Record(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case AggregationTimeTagType:
                        _aggregationTime = new IntegerTag(this[i]);
                        this[i] = _aggregationTime;
                        break;
                    case ChainIndexTagType:
                        IntegerTag chainTag = new IntegerTag(this[i]);
                        _chainIndex.Add(chainTag);
                        this[i] = chainTag;
                        break;
                    case InputHashTagType:
                        _inputHash = new ImprintTag(this[i]);
                        this[i] = _inputHash;
                        break;
                    case TstInfoPrefixTagType:
                        _tstInfoPrefix = new RawTag(this[i]);
                        this[i] = _tstInfoPrefix;
                        break;
                    case TstInfoSuffixTagType:
                        _tstInfoSuffix = new RawTag(this[i]);
                        this[i] = _tstInfoSuffix;
                        break;
                    case TstInfoAlgorithmTagType:
                        _tstInfoAlgorithm = new IntegerTag(this[i]);
                        this[i] = _tstInfoAlgorithm;
                        break;
                    case SignedAttributesPrefixTagType:
                        _signedAttributesPrefix = new RawTag(this[i]);
                        this[i] = _signedAttributesPrefix;
                        break;
                    case SignedAttributesSuffixTagType:
                        _signedAttributesSuffix = new RawTag(this[i]);
                        this[i] = _signedAttributesSuffix;
                        break;
                    case SignedAttributesAlgorithmTagType:
                        _signedAttributesAlgorithm = new IntegerTag(this[i]);
                        this[i] = _signedAttributesAlgorithm;
                        break;
                }
            }
        }

        /// <summary>
        /// Get output hash for RFC 3161 from document hash
        /// </summary>
        /// <param name="inputHash">document hash</param>
        /// <returns>aggregation input hash</returns>
        public DataHash GetOutputHash(DataHash inputHash)
        {
            if (inputHash == null)
            {
                throw new ArgumentNullException("inputHash");
            }

            // TODO: Check data before using them

            DataHasher hasher = new DataHasher(HashAlgorithm.GetById((byte)_tstInfoAlgorithm.Value));
            hasher.AddData(_tstInfoPrefix.Value);
            hasher.AddData(inputHash.Imprint);
            hasher.AddData(_tstInfoSuffix.Value);

            inputHash = hasher.GetHash();

            hasher = new DataHasher(HashAlgorithm.GetById((byte)_signedAttributesAlgorithm.Value));
            hasher.AddData(_signedAttributesPrefix.Value);
            hasher.AddData(inputHash.Imprint);
            hasher.AddData(_signedAttributesSuffix.Value);

            return hasher.GetHash();
        }

        /// <summary>
        /// Check TLV structure.
        /// </summary>
        protected override void CheckStructure()
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid RFC 3161 record type: " + Type);
            }

            uint[] tags = new uint[9];

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case AggregationTimeTagType:
                        tags[0]++;
                        break;
                    case ChainIndexTagType:
                        tags[1]++;
                        break;
                    case InputHashTagType:
                        tags[2]++;
                        break;
                    case TstInfoPrefixTagType:
                        tags[3]++;
                        break;
                    case TstInfoSuffixTagType:
                        tags[4]++;
                        break;
                    case TstInfoAlgorithmTagType:
                        tags[5]++;
                        break;
                    case SignedAttributesPrefixTagType:
                        tags[6]++;
                        break;
                    case SignedAttributesSuffixTagType:
                        tags[7]++;
                        break;
                    case SignedAttributesAlgorithmTagType:
                        tags[8]++;
                        break;
                    default:
                        throw new InvalidTlvStructureException("Invalid tag", this[i]);
                }
            }

            if (tags[0] != 1)
            {
                throw new InvalidTlvStructureException("Only one aggregation time must exist in RFC 3161 record");
            }

            if (tags[1] == 0)
            {
                throw new InvalidTlvStructureException("Chain indexes must exist in RFC 3161 record");
            }

            if (tags[2] != 1)
            {
                throw new InvalidTlvStructureException("Only one input hash must exist in RFC 3161 record");
            }

            if (tags[3] != 1)
            {
                throw new InvalidTlvStructureException("Only one tstInfo prefix must exist in RFC 3161 record");
            }

            if (tags[4] != 1)
            {
                throw new InvalidTlvStructureException("Only one tstInfo suffix must exist in RFC 3161 record");
            }

            if (tags[5] != 1)
            {
                throw new InvalidTlvStructureException("Only one tstInfo algorithm must exist in RFC 3161 record");
            }

            if (tags[6] != 1)
            {
                throw new InvalidTlvStructureException("Only one signed attributes prefix must exist in RFC 3161 record");
            }

            if (tags[7] != 1)
            {
                throw new InvalidTlvStructureException("Only one signed attributes suffix must exist in RFC 3161 record");
            }

            if (tags[8] != 1)
            {
                throw new InvalidTlvStructureException("Only one signed attributes algorithm must exist in RFC 3161 record");
            }
        }
    }
}