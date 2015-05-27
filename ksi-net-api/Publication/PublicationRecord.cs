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
            set
            {
                PutTag(value, _publicationData);
                _publicationData = value;
            }
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
            for (int i = 0; i < Value.Count; i++)
            {
                StringTag listTag;

                switch (Value[i].Type)
                {
                    case 0x10:
                        _publicationData = new PublicationData(Value[i]);
                        Value[i] = _publicationData;
                        break;
                    case 0x9:
                        listTag = new StringTag(Value[i]);
                        AddPublicationReference(listTag);
                        Value[i] = listTag;
                        break;
                    case 0xA:
                        listTag = new StringTag(Value[i]);
                        AddPublicationRepositoryUri(listTag);
                        Value[i] = listTag;
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