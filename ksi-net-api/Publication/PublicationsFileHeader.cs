using System;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    internal class PublicationsFileHeader : CompositeTag
    {
        public IntegerTag Version { get; }
        public IntegerTag CreationTime { get; }
        public StringTag RepUri { get; }

        public PublicationsFileHeader(TlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
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

        public override bool IsValidStructure()
        {
            throw new NotImplementedException();
        }
    }
}