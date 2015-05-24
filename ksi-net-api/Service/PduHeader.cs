using System;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    class PduHeader : CompositeTag
    {
        private StringTag _loginId;
        private IntegerTag _instanceId;
        private IntegerTag _messageId;

        public PduHeader(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x1:
                        _loginId = new StringTag(Value[i]);
                        Value[i] = _loginId;
                        break;
                    case 0x2:
                        _instanceId = new IntegerTag(Value[i]);
                        Value[i] = _instanceId;
                        break;
                    case 0x3:
                        _messageId = new IntegerTag(Value[i]);
                        Value[i] = _messageId;
                        break;
                }
            }
        }
        
        // TODO: Create correct constructor
        public PduHeader() : base(0x1, false, false)
        {
            _loginId = new StringTag(0x1, false, false, "anon");
            Value.Add(_loginId);

            _instanceId = new IntegerTag(0x2, false, false, 0);
            Value.Add(_instanceId);

            _messageId = new IntegerTag(0x3, false, false, 0);
            Value.Add(_messageId);
        }

        public override bool IsValidStructure()
        {
            throw new NotImplementedException();
        }
    }
}
