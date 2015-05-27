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
            for (int i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x1:
                        Version = new IntegerTag(Value[i]);
                        Value[i] = Version;
                        break;
                    case 0x2:
                        CreationTime = new IntegerTag(Value[i]);
                        Value[i] = CreationTime;
                        break;
                    case 0x3:
                        RepUri = new StringTag(Value[i]);
                        Value[i] = RepUri;
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