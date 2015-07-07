using Guardtime.KSI.Parser;
using System;
using System.Collections.Generic;

namespace Guardtime.KSI.Service
{
    internal class ExtendPdu : KsiPdu
    {
        // TODO: Better name
        public const uint TagType = 0x300;

        private readonly ExtendPduPayload _payload;

        public override KsiPduPayload Payload
        {
            get
            {
                return _payload;
            }
        }

        public ExtendPdu(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case ExtendResponsePayload.TagType:
                        _payload = new ExtendResponsePayload(this[i]);
                        this[i] = _payload;
                        break;
                    case ExtendError.TagType:
                        _payload = new ExtendError(this[i]);
                        this[i] = _payload;
                        break;
                }
            }
        }

        // TODO: Create correct constructor
        public ExtendPdu(KsiPduHeader header, ExtendPduPayload payload) : base(header, TagType, false, false, new List<TlvTag>())
        {
            _payload = payload;
            if (payload != null)
            {
                AddTag(_payload);
            }
        }

        

        protected override void CheckStructure()
        {
            // TODO: Check if payload exists
        }
    }
}