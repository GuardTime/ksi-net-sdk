using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class PublicationRecord : CompositeTag
    {

        protected PublicationData PublicationData;

        protected List<StringTag> PublicationReferences;

        protected List<StringTag> PubRepUri;

        public PublicationRecord(TlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x10:
                        PublicationData = new PublicationData(Value[i]);
                        break;
                    case 0x9:
                        if (PublicationReferences == null)
                        {
                            PublicationReferences = new List<StringTag>();
                        }

                        var publicationReferenceTag = new StringTag(Value[i]);
                        PublicationReferences.Add(publicationReferenceTag);
                        Value[i] = publicationReferenceTag;
                        break;
                    case 0xA:
                        if (PubRepUri == null)
                        {
                            PubRepUri = new List<StringTag>();
                        }

                        var pubRepUriTag = new StringTag(Value[i]);
                        PubRepUri.Add(pubRepUriTag);
                        Value[i] = pubRepUriTag;
                        break;
                }
            }
        }

        
    }
}