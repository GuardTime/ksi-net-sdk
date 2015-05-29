using System;
using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class PublicationRecord : CompositeTag
    {

        private PublicationData _publicationData;
        private List<StringTag> _publicationReferences;
        private List<StringTag> _publicationRepositoryUri;

        public PublicationData PublicationData
        {
            get { return _publicationData; }
        }

        public List<StringTag> PublicationReferences
        {
            get { return _publicationReferences; }
        }

        public List<StringTag> PubRepUri
        {
            get { return _publicationRepositoryUri; }
        }

        public DateTime PublicationTime
        {
            get
            {
                return Util.Util.ConvertUnixTimeToDateTime(PublicationData.PublicationTime.Value);
            } 
        } 

        public PublicationRecord(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                StringTag listTag;

                switch (this[i].Type)
                {
                    case 0x10:
                        _publicationData = new PublicationData(this[i]);
                        this[i] = _publicationData;
                        break;
                    case 0x9:
                        listTag = new StringTag(this[i]);
                        AddPublicationReference(listTag);
                        this[i] = listTag;
                        break;
                    case 0xA:
                        listTag = new StringTag(this[i]);
                        AddPublicationRepositoryUri(listTag);
                        this[i] = listTag;
                        break;
                }
            }
        }

        public void AddPublicationReference(StringTag tag)
        {
            if (_publicationReferences == null)
            {
                _publicationReferences = new List<StringTag>();
            }

            _publicationReferences.Add(tag);
        }

        public void AddPublicationRepositoryUri(StringTag tag)
        {
            if (_publicationRepositoryUri == null)
            {
                _publicationRepositoryUri = new List<StringTag>();
            }

            _publicationRepositoryUri.Add(tag);
        }

        protected override void CheckStructure()
        {
            throw new NotImplementedException();
        }
    }
}