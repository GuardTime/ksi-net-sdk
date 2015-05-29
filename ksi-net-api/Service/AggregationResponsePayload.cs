using System;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    public class AggregationResponsePayload : AggregationPduPayload
    {
        private IntegerTag _requestId;
        private IntegerTag _status;
        private StringTag _errorMessage;

        // TODO: Create config
        private RawTag _config;
        // TODO: Create request acknowledgement 
        private RawTag _requestAckonolodgement;

        public AggregationResponsePayload(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < this.Count; i++)
            {
                switch (this[i].Type)
                {
                    case 0x1:
                        _requestId = new IntegerTag(this[i]);
                        this[i] = _requestId;
                        break;
                    case 0x4:
                        _status = new IntegerTag(this[i]);
                        this[i] = _status;
                        break;
                    case 0x5:
                        _errorMessage = new StringTag(this[i]);
                        this[i] = _errorMessage;
                        break;
                    case 0x10:
                        _config = new RawTag(this[i]);
                        this[i] = _config;
                        break;
                    case 0x11:
                        _requestAckonolodgement = new RawTag(this[i]);
                        this[i] = _requestAckonolodgement;
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
