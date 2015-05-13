using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class PublicationData : CompositeTag
    {
        private IntegerTag _publicationTime;
        private ImprintTag _publicationHash;

        public PublicationData(TlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x2:
                        _publicationTime = new IntegerTag(Value[i]);
                        Value[i] = _publicationTime;
                        break;
                    case 0x4:
                        _publicationHash = new ImprintTag(Value[i]);
                        Value[i] = _publicationHash;
                        break;
                }
            }
        }


    }
}
