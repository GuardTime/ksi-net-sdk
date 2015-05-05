using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class PublicationData : ICompositeTag
    {
        private IntegerTag _publicationTime;
        private ImprintTag _publicationHash;

        public ITlvTag GetMember(ITlvTag tag)
        {
            switch (tag.Type)
            {
                case 0x2:
                    _publicationTime = new IntegerTag(tag);
                    return _publicationTime;
                case 0x4:
                    _publicationHash = new ImprintTag(tag);
                    return _publicationHash;
            }

            return null;
        }
    }
}
