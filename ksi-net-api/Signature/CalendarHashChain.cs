using System;
using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    public class CalendarHashChain : CompositeTag
    {
        protected IntegerTag PublicationTime;

        protected IntegerTag AggregationTime;

        protected ImprintTag InputHash;

        protected List<Link> Chain;

        public CalendarHashChain(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x1:
                        PublicationTime = new IntegerTag(Value[i]);
                        Value[i] = PublicationTime;
                        break;
                    case 0x2:
                        AggregationTime = new IntegerTag(Value[i]);
                        Value[i] = AggregationTime;
                        break;
                    case 0x5:
                        InputHash = new ImprintTag(Value[i]);
                        Value[i] = InputHash;
                        break;
                    case 0x7:
                    case 0x8:
                        if (Chain == null)
                        {
                            Chain = new List<Link>();
                        }

                        Link chainTag = new Link(Value[i]);
                        Chain.Add(chainTag);
                        Value[i] = chainTag;
                        break;
                }
            }
        }

        protected class Link : ImprintTag
        {
            private LinkDirection _direction;

            public Link(TlvTag tag) : base(tag)
            {
                if (tag.Type == (int) LinkDirection.Left)
                {
                    _direction = LinkDirection.Left;
                }

                if (tag.Type == (int) LinkDirection.Right)
                {
                    _direction = LinkDirection.Right;
                }

                if (_direction == 0)
                {
                    // TODO: Correct exception and fix all System.Exception
                    throw new Exception("Invalid link direction");
                }
                
            }
            
        }


        protected override void CheckStructure()
        {
            // TODO:
        }
    }
}