using Guardtime.KSI.Parser;
using System.Collections.Generic;

namespace Guardtime.KSI.Publication
{
    public class PublicationRecord : ICompositeTag
    {

        protected CompositeTag<PublicationData> publicationData;

        protected List<StringTag> publicationReferences;

        protected List<StringTag> pubRepUri;

        public ITlvTag GetMember(ITlvTag tag)
        {

            switch (tag.Type)
            {
                case 0x10:
                    publicationData = new CompositeTag<PublicationData>(tag, new PublicationData());
                    return publicationData;
                case 0x9:
                    if (publicationReferences == null)
                    {
                        publicationReferences = new List<StringTag>();
                    }

                    var publicationReferenceTag = new StringTag(tag);
                    publicationReferences.Add(publicationReferenceTag);
                    return publicationReferenceTag;
                case 0xA:
                    if (pubRepUri == null)
                    {
                        pubRepUri = new List<StringTag>();
                    }

                    var pubRepUriTag = new StringTag(tag);
                    pubRepUri.Add(pubRepUriTag);
                    return pubRepUriTag;
            }

            return null;
    }
    }
}