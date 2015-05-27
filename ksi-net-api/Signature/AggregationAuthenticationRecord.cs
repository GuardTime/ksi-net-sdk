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

        public AggregationAuthenticationRecord(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x2:
                        _aggregationTime = new IntegerTag(Value[i]);
                        Value[i] = _aggregationTime;
                        break;
                    case 0x3:
                        if (_chainIndex == null)
                        {
                            _chainIndex = new List<IntegerTag>();
                        }

                        IntegerTag chainIndexTag = new IntegerTag(Value[i]);
                        _chainIndex.Add(chainIndexTag);
                        Value[i] = chainIndexTag;
                        break;
                    case 0x5:
                        _inputHash = new ImprintTag(Value[i]);
                        Value[i] = _inputHash;
                        break;
                    case 0xB:
                        _signatureData = new SignatureData(Value[i]);
                        Value[i] = _signatureData;
                        break;
                }
            }
        }

        protected override void CheckStructure()
        {
            throw new System.NotImplementedException();
        }
    }
}