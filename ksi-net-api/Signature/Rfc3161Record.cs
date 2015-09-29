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
        // TODO: Better name
        /// <summary>
        ///     RFC3161 record tag type
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
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public Rfc3161Record(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
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

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case AggregationTimeTagType:
                        _aggregationTime = new IntegerTag(this[i]);
                        this[i] = _aggregationTime;
                        aggregationTimeCount++;
                        break;
                    case ChainIndexTagType:
                        IntegerTag chainTag = new IntegerTag(this[i]);
                        _chainIndex.Add(chainTag);
                        this[i] = chainTag;
                        break;
                    case InputHashTagType:
                        _inputHash = new ImprintTag(this[i]);
                        this[i] = _inputHash;
                        inputHashCount++;
                        break;
                    case TstInfoPrefixTagType:
                        _tstInfoPrefix = new RawTag(this[i]);
                        this[i] = _tstInfoPrefix;
                        tstInfoPrefixCount++;
                        break;
                    case TstInfoSuffixTagType:
                        _tstInfoSuffix = new RawTag(this[i]);
                        this[i] = _tstInfoSuffix;
                        tstInfoSuffixCount++;
                        break;
                    case TstInfoAlgorithmTagType:
                        _tstInfoAlgorithm = new IntegerTag(this[i]);
                        this[i] = _tstInfoAlgorithm;
                        tstInfoAlgorithmCount++;
                        break;
                    case SignedAttributesPrefixTagType:
                        _signedAttributesPrefix = new RawTag(this[i]);
                        this[i] = _signedAttributesPrefix;
                        signedAttributesPrefixCount++;
                        break;
                    case SignedAttributesSuffixTagType:
                        _signedAttributesSuffix = new RawTag(this[i]);
                        this[i] = _signedAttributesSuffix;
                        signedAttributesSuffixCount++;
                        break;
                    case SignedAttributesAlgorithmTagType:
                        _signedAttributesAlgorithm = new IntegerTag(this[i]);
                        this[i] = _signedAttributesAlgorithm;
                        signedAttributesAlgorithmCount++;
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
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
        public ulong AggregationTime
        {
            get { return _aggregationTime.Value; }
        }

        /// <summary>
        ///     Get RFC3161 input hash
        /// </summary>
        public DataHash InputHash
        {
            get { return _inputHash.Value; }
        }

        /// <summary>
        ///     Get output hash for RFC 3161 from document hash
        /// </summary>
        /// <param name="inputHash">document hash</param>
        /// <returns>aggregation input hash</returns>
        /// <exception cref="KsiException">thrown when input hash is null</exception>
        public DataHash GetOutputHash(DataHash inputHash)
        {
            if (inputHash == null)
            {
                throw new KsiException("Invalid input hash: null.");
            }

            DataHasher hasher = new DataHasher(HashAlgorithm.GetById((byte) _tstInfoAlgorithm.Value));
            hasher.AddData(_tstInfoPrefix.Value);
            hasher.AddData(inputHash.Value);
            hasher.AddData(_tstInfoSuffix.Value);

            inputHash = hasher.GetHash();

            hasher = new DataHasher(HashAlgorithm.GetById((byte) _signedAttributesAlgorithm.Value));
            hasher.AddData(_signedAttributesPrefix.Value);
            hasher.AddData(inputHash.Value);
            hasher.AddData(_signedAttributesSuffix.Value);

            return hasher.GetHash();
        }
    }
}