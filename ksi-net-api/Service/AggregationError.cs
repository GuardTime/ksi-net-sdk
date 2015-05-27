using System;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    public class AggregationError : AggregationPduPayload
    {
        private IntegerTag _status;
        private StringTag _errorMessage;

        public AggregationError(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x4:
                        _status = new IntegerTag(Value[i]);
                        Value[i] = _status;
                        break;
                    case 0x5:
                        _errorMessage = new StringTag(Value[i]);
                        Value[i] = _errorMessage;
                        break;
                }
            }
        }

        protected override void CheckStructure()
        {
            throw new NotImplementedException();
        }

    }
}
