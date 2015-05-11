using System;
using System.Collections.Generic;

namespace Guardtime.KSI.Parse
{
    public class PublicationRecord : TlvElement
    {

        protected PublicationData PublicationData;

        protected List<TlvElement> PublicationReferences;

        protected List<TlvElement> PubRepUri;

        public PublicationRecord(byte[] bytes) : base(bytes)
        {
            Content = new CompositeContent(Content.EncodeValue());
            Console.WriteLine(this);
            //            for (var i = 0; i < Content.Value; i++)
            //            {
            //                switch (Value[i].Type)
            //                {
            //                    case 0x10:
            //                        Value[i] = PublicationData = new PublicationData(Value[i]);
            //                        break;
            //                    case 0x9:
            //                        if (PublicationReferences == null)
            //                        {
            //                            PublicationReferences = new List<StringTag>();
            //                        }

            //                        var publicationReferenceTag = new StringTag(Value[i]);
            //                        PublicationReferences.Add(publicationReferenceTag);
            //                        Value[i] = publicationReferenceTag;
            //                        break;
            //                    case 0xA:
            //                        if (PubRepUri == null)
            //                        {
            //                            PubRepUri = new List<StringTag>();
            //                        }

            //                        var pubRepUriTag = new StringTag(Value[i]);
            //                        PubRepUri.Add(pubRepUriTag);
            //                        Value[i] = pubRepUriTag;
            //                        break;
            //                }
        }
        }

        
    }
}