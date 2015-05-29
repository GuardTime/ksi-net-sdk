using System;
using System.Collections.Generic;
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
            for (int i = 0; i < this.Count; i++)
            {
                switch (this[i].Type)
                {
                    case 0x1:
                        _loginId = new StringTag(this[i]);
                        this[i] = _loginId;
                        break;
                    case 0x2:
                        _instanceId = new IntegerTag(this[i]);
                        this[i] = _instanceId;
                        break;
                    case 0x3:
                        _messageId = new IntegerTag(this[i]);
                        this[i] = _messageId;
                        break;
                }
            }
        }
        
        // TODO: Create correct constructor
        public PduHeader(string loginId) : base(0x1, false, false, new List<TlvTag>())
        {
            _loginId = new StringTag(0x1, false, false, loginId);
            this.AddTag(_loginId);

            _instanceId = new IntegerTag(0x2, false, false, 0);
            this.AddTag(_instanceId);

            _messageId = new IntegerTag(0x3, false, false, 0);
            this.AddTag(_messageId);
        }

        protected override void CheckStructure()
        {
            throw new NotImplementedException();
        }
    }
}
