using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    public class AggregationAuthenticationRecord : CompositeTag
    {

        private IntegerTag _aggregationTime;

        private List<IntegerTag> _chainIndex;

        private ImprintTag _inputHash;

        private SignatureData _signatureData;

        public AggregationAuthenticationRecord(ITlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x2:
                        Value[i] = _aggregationTime = new IntegerTag(Value[i]);
                        break;
                    case 0x3:
                        if (_chainIndex == null)
                        {
                            _chainIndex = new List<IntegerTag>();
                        }

                        var chainIndexTag = new IntegerTag(Value[i]);
                        _chainIndex.Add(chainIndexTag);
                        Value[i] = chainIndexTag;
                        break;
                    case 0x5:
                        Value[i] = _inputHash = new ImprintTag(Value[i]);
                        break;
                    case 0xB:
                        Value[i] = _signatureData = new SignatureData(Value[i]);
                        break;
                }
            }
        }
    }
}