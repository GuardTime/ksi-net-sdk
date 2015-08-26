using System.Collections.Generic;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    /// Aggregation authentication record TLV element
    /// </summary>
    public sealed class AggregationAuthenticationRecord : CompositeTag
    {
        // TODO: Better name
        /// <summary>
        /// Aggregation authentication record tag type
        /// </summary>
        public const uint TagType = 0x804;
        private const uint AggregationTimeTagType = 0x2;
        private const uint ChainIndexTagType = 0x3;
        private const uint InputHashTagType = 0x5;

        private readonly IntegerTag _aggregationTime;
        private readonly List<IntegerTag> _chainIndex = new List<IntegerTag>();
        private readonly ImprintTag _inputHash;
        private readonly SignatureData _signatureData;

        /// <summary>
        /// Create new aggregation authentication record TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationAuthenticationRecord(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid aggregation authentication record type: " + Type);
            }

            int aggregationTimeCount = 0;
            int inputHashCount = 0;
            int signatureDataCount = 0;

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
                        IntegerTag chainIndexTag = new IntegerTag(this[i]);
                        _chainIndex.Add(chainIndexTag);
                        this[i] = chainIndexTag;
                        break;
                    case InputHashTagType:
                        _inputHash = new ImprintTag(this[i]);
                        this[i] = _inputHash;
                        inputHashCount++;
                        break;
                    case SignatureData.TagType:
                        _signatureData = new SignatureData(this[i]);
                        this[i] = _signatureData;
                        signatureDataCount++;
                        break;
                    default:
                        VerifyCriticalTag(this[i]);
                        break;

                }
            }

            if (aggregationTimeCount != 1)
            {
                throw new InvalidTlvStructureException("Only one aggregation time must exist in aggregation authentication record");
            }

            if (_chainIndex.Count == 0)
            {
                throw new InvalidTlvStructureException("Chain indexes must exist in aggregation authentication record");
            }

            if (inputHashCount != 1)
            {
                throw new InvalidTlvStructureException("Only one input hash must exist in aggregation authentication record");
            }

            if (signatureDataCount != 1)
            {
                throw new InvalidTlvStructureException("Only one signature data must exist in aggregation authentication record");
            }
        }

    }
}