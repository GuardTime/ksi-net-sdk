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
            for (int i = 0; i < this.Count; i++)
            {
                switch (this[i].Type)
                {
                    case 0x4:
                        _status = new IntegerTag(this[i]);
                        this[i] = _status;
                        break;
                    case 0x5:
                        _errorMessage = new StringTag(this[i]);
                        this[i] = _errorMessage;
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
