﻿using System;
using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    public class AggregationPdu : KsiPdu
    {
        // TODO: Better name
        public const uint TagType = 0x200;

        private readonly AggregationPduPayload _payload;

        public override KsiPduPayload Payload
        {
            get
            {
                return _payload;
            }
        }

        public AggregationPdu(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case AggregationResponsePayload.TagType:
                        _payload = new AggregationResponsePayload(this[i]);
                        this[i] = _payload;
                        break;
                    case AggregationError.TagType:
                        _payload = new AggregationError(this[i]);
                        this[i] = _payload;
                        break;
                }
            }
        }

        public AggregationPdu(KsiPduHeader header, AggregationPduPayload payload) : base(header, TagType, false, false, new List<TlvTag>())
        {
            _payload = payload;
            if (payload != null)
            {
                AddTag(_payload);
            }
        }

        protected override void CheckStructure()
        {
            throw new NotImplementedException();
        }
    }
}
