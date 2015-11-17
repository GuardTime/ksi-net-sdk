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
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
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

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case Constants.Rfc3161Record.AggregationTimeTagType:
                        _aggregationTime = new IntegerTag(this[i]);
                        aggregationTimeCount++;
                        break;
                    case Constants.Rfc3161Record.ChainIndexTagType:
                        IntegerTag chainTag = new IntegerTag(this[i]);
                        _chainIndex.Add(chainTag);
                        break;
                    case Constants.Rfc3161Record.InputHashTagType:
                        _inputHash = new ImprintTag(this[i]);
                        inputHashCount++;
                        break;
                    case Constants.Rfc3161Record.TstInfoPrefixTagType:
                        _tstInfoPrefix = new RawTag(this[i]);
                        tstInfoPrefixCount++;
                        break;
                    case Constants.Rfc3161Record.TstInfoSuffixTagType:
                        _tstInfoSuffix = new RawTag(this[i]);
                        tstInfoSuffixCount++;
                        break;
                    case Constants.Rfc3161Record.TstInfoAlgorithmTagType:
                        _tstInfoAlgorithm = new IntegerTag(this[i]);
                        tstInfoAlgorithmCount++;
                        break;
                    case Constants.Rfc3161Record.SignedAttributesPrefixTagType:
                        _signedAttributesPrefix = new RawTag(this[i]);
                        signedAttributesPrefixCount++;
                        break;
                    case Constants.Rfc3161Record.SignedAttributesSuffixTagType:
                        _signedAttributesSuffix = new RawTag(this[i]);
                        signedAttributesSuffixCount++;
                        break;
                    case Constants.Rfc3161Record.SignedAttributesAlgorithmTagType:
                        _signedAttributesAlgorithm = new IntegerTag(this[i]);
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
        /// <exception cref="KsiException">thrown when input hash is null</exception>
        public DataHash GetOutputHash(DataHash inputHash)
        {
            if (inputHash == null)
            {
                throw new KsiException("Invalid input hash: null.");
            }

            DataHasher hasher = new DataHasher(HashAlgorithm.GetById((byte)_tstInfoAlgorithm.Value));
            hasher.AddData(_tstInfoPrefix.Value);
            hasher.AddData(inputHash.Value);
            hasher.AddData(_tstInfoSuffix.Value);

            inputHash = hasher.GetHash();

            hasher = new DataHasher(HashAlgorithm.GetById((byte)_signedAttributesAlgorithm.Value));
            hasher.AddData(_signedAttributesPrefix.Value);
            hasher.AddData(inputHash.Value);
            hasher.AddData(_signedAttributesSuffix.Value);

            return hasher.GetHash();
        }
    }
}