using System;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    internal class PublicationsFileHeader : CompositeTag
    {
        public IntegerTag Version;
        public IntegerTag CreationTime;
        public StringTag RepUri;

        public PublicationsFileHeader(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < this.Count; i++)
            {
                switch (this[i].Type)
                {
                    case 0x1:
                        Version = new IntegerTag(this[i]);
                        this[i] = Version;
                        break;
                    case 0x2:
                        CreationTime = new IntegerTag(this[i]);
                        this[i] = CreationTime;
                        break;
                    case 0x3:
                        RepUri = new StringTag(this[i]);
                        this[i] = RepUri;
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