using System;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class PublicationsFile : ICompositeTag
    {
        private CompositeTag<PublicationData> _publicationData;

        public ITlvTag GetMember(ITlvTag tag)
        {
            switch (tag.Type)
            {
                case 0x10:
                    _publicationData = new CompositeTag<PublicationData>(tag, new PublicationData());
                    return _publicationData;
            }

            return null;
        }
    }
}
