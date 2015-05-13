using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    public class Rfc3161Record : CompositeTag
    {
        protected IntegerTag AggregationTime;
        protected List<IntegerTag> ChainIndex;
        protected ImprintTag InputHash;

        protected TlvTag TstInfoPrefix;
        protected TlvTag TstInfoSuffix;
        protected IntegerTag TstInfoAlgorithm;

        protected TlvTag SignedAttributesPrefix;
        protected TlvTag SignedAttributesSuffix;
        protected IntegerTag SignedAttributesAlgorithm;

        public Rfc3161Record(TlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x2:
                        AggregationTime = new IntegerTag(Value[i]);
                        Value[i] = AggregationTime;
                        break;
                    case 0x3:
                        if (ChainIndex == null)
                        {
                            ChainIndex = new List<IntegerTag>();
                        }

                        var chainTag = new IntegerTag(Value[i]);
                        ChainIndex.Add(chainTag);
                        Value[i] = chainTag;
                        break;
                    case 0x5:
                        InputHash = new ImprintTag(Value[i]);
                        Value[i] = InputHash;
                        break;
                    case 0x10:
                        TstInfoPrefix = Value[i];
                        break;
                    case 0x11:
                        TstInfoSuffix = new TlvTag(Value[i]);
                        Value[i] = TstInfoSuffix;
                        break;
                    case 0x12:
                        TstInfoAlgorithm = new IntegerTag(Value[i]);
                        Value[i] = TstInfoAlgorithm;
                        break;
                    case 0x13:
                        SignedAttributesPrefix =Value[i];
                        break;
                    case 0x14:
                        SignedAttributesSuffix = Value[i];
                        break;
                    case 0x15:
                        SignedAttributesAlgorithm = new IntegerTag(Value[i]);
                        Value[i] = SignedAttributesAlgorithm;
                        break;
                }
            }
        }
    }
}