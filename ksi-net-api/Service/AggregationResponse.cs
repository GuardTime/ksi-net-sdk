using System;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    class AggregationResponse : AggregationPduPayload
    {
        private IntegerTag _requestId;
        private IntegerTag _status;
        private StringTag _errorMessage;

        // TODO: Create config
        private RawTag _config;
        // TODO: Create request acknowledgement 
        private RawTag _requestAckonolodgement;

        public AggregationResponse(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x1:
                        _requestId = new IntegerTag(Value[i]);
                        Value[i] = _requestId;
                        break;
                    case 0x4:
                        _status = new IntegerTag(Value[i]);
                        Value[i] = _status;
                        break;
                    case 0x5:
                        _errorMessage = new StringTag(Value[i]);
                        Value[i] = _errorMessage;
                        break;
                    case 0x10:
                        _config = new RawTag(Value[i]);
                        Value[i] = _config;
                        break;
                    case 0x11:
                        _requestAckonolodgement = new RawTag(Value[i]);
                        Value[i] = _requestAckonolodgement;
                        break;
                }
            }
        }

        public override bool IsValidStructure()
        {
            throw new NotImplementedException();
        }

    }
}
