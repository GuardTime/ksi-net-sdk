using Guardtime.KSI.Parser;
using System;
using System.Collections.Generic;

namespace Guardtime.KSI.Signature
{
    public class CalendarHashChain : ICompositeTag
    {
        protected IntegerTag publicationTime;

        protected IntegerTag aggregationTime;

        protected ImprintTag inputHash;

        protected List<Link> chain;

        public ITlvTag GetMember(ITlvTag tag)
        {

            switch (tag.Type)
            {
                case 0x1:
                    publicationTime = new IntegerTag(tag);
                    return publicationTime;
                case 0x2:
                    aggregationTime = new IntegerTag(tag);
                    return aggregationTime;
                case 0x5:
                    inputHash = new ImprintTag(tag);
                    return inputHash;
                case 0x7:
                case 0x8:
                    if (chain == null)
                    {
                        chain = new List<Link>();
                    }

                    var chainTag = new Link(tag);
                    chain.Add(chainTag);
                    return chainTag;
            }

            return null;
        }

        protected class Link : ImprintTag
        {
            private LinkDirection direction;

            /**
             * Create new hash chain link.
             * @param tag base TLVTag
             * @throws FormatException if parsing object from TLVTag fails
             */
            public Link(ITlvTag tag) : base(tag)
            {
                if (Type == (uint)LinkDirection.LEFT)
                {
                    direction = LinkDirection.LEFT;
                }

                if (Type == (uint)LinkDirection.RIGHT)
                {
                    direction = LinkDirection.RIGHT;
                }

                if (direction == 0)
                {
                    throw new FormatException("Attempt to construct calendar link form tag type " + Type);
                }
            }
        }

        
    }
}