using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class PublicationData : CompositeTag
    {
        private IntegerTag _publicationTime;
        private ImprintTag _publicationHash;

        public PublicationData(ITlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x2:
                        Value[i] = _publicationTime = new IntegerTag(Value[i]);
                        break;
                    case 0x4:
                        Value[i] = _publicationHash = new ImprintTag(Value[i]);
                        break;
                }
            }
        }


    }
}
