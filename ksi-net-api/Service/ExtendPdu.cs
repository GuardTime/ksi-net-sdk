using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using System;
using System.Collections.Generic;

namespace Guardtime.KSI.Service
{
    public sealed class ExtendPdu : KsiPdu
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
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid extend pdu type: " + Type);
            }

            int payloadCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case ExtendResponsePayload.TagType:
                        _payload = new ExtendResponsePayload(this[i]);
                        this[i] = _payload;
                        payloadCount++;
                        break;
                    case ExtendError.TagType:
                        _payload = new ExtendError(this[i]);
                        this[i] = _payload;
                        payloadCount++;
                        break;
                    // TODO: Better solution for parent tags
                    case KsiPduHeader.TagType:
                    case MacTagType:
                        break;
                    default:
                        VerifyCriticalTag(this[i]);
                        break;
                }
            }

            if (payloadCount != 1)
            {
                throw new InvalidTlvStructureException("Only one payload must exist in ksi pdu");
            }
        }

        // TODO: Create correct constructor
        public ExtendPdu(KsiPduHeader header, ExtendPduPayload payload) : base(header, TagType, false, false, new List<TlvTag>())
        {
            if (payload == null)
            {
                throw new ArgumentNullException("payload");
            }

            _payload = AddTag(payload);
        }

    }
}