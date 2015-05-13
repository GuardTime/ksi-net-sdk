using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    internal class PublicationFileHeader : CompositeTag
    {
        private IntegerTag _version;

        private IntegerTag _creationTime;

        private StringTag _repUri;

        public PublicationFileHeader(TlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x1:
                        _version = new IntegerTag(Value[i]);
                        Value[i] = _version;
                        break;
                    case 0x2:
                        _creationTime = new IntegerTag(Value[i]);
                        Value[i] = _creationTime;
                        break;
                    case 0x3:
                        _repUri = new StringTag(Value[i]);
                        Value[i] = _repUri;
                        break;
                }
            }
        }
        
    }
}