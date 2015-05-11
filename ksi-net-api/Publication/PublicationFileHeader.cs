using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    internal class PublicationFileHeader : CompositeTag
    {
        private IntegerTag _version;

        private IntegerTag _creationTime;

        private StringTag _repUri;

        public PublicationFileHeader(ITlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x1:
                        Value[i] = _version = new IntegerTag(Value[i]);
                        break;
                    case 0x2:
                        Value[i] = _creationTime = new IntegerTag(Value[i]);
                        break;
                    case 0x3:
                        Value[i] = _repUri = new StringTag(Value[i]);
                        break;
                }
            }
        }
        
    }
}