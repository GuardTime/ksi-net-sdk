using System;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class PublicationsFile : CompositeTag
    {
        private PublicationData _publicationData;

        public PublicationsFile(ITlvTag tag)
            : base(tag)
        {
            
        }

        public override ITlvTag GetMember(ITlvTag tag)
        {
            switch (tag.Type)
            {
                case 0x10:
                    _publicationData = new PublicationData(tag);
                    return _publicationData;
            }

            return null;
        }
    }
}
