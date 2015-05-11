using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    public class Rfc3161Record : CompositeTag
    {
        protected IntegerTag AggregationTime;
        protected List<IntegerTag> ChainIndex;
        protected ImprintTag InputHash;

        protected RawTag TstInfoPrefix;
        protected RawTag TstInfoSuffix;
        protected IntegerTag TstInfoAlgorithm;

        protected RawTag SignedAttributesPrefix;
        protected RawTag SignedAttributesSuffix;
        protected IntegerTag SignedAttributesAlgorithm;

        public Rfc3161Record(ITlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x2:
                        Value[i] = AggregationTime = new IntegerTag(Value[i]);
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
                        Value[i] = InputHash = new ImprintTag(Value[i]);
                        break;
                    case 0x10:
                        Value[i] = TstInfoPrefix = new RawTag(Value[i]);
                        break;
                    case 0x11:
                        Value[i] = TstInfoSuffix = new RawTag(Value[i]);
                        break;
                    case 0x12:
                        Value[i] = TstInfoAlgorithm = new IntegerTag(Value[i]);
                        break;
                    case 0x13:
                        Value[i] = SignedAttributesPrefix = new RawTag(Value[i]);
                        break;
                    case 0x14:
                        Value[i] = SignedAttributesSuffix = new RawTag(Value[i]);
                        break;
                    case 0x15:
                        Value[i] = SignedAttributesAlgorithm = new IntegerTag(Value[i]);
                        break;
                }
            }
        }
    }
}