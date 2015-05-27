using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class PublicationData : CompositeTag
    {
        private IntegerTag _publicationTime;
        private ImprintTag _publicationHash;

        public IntegerTag PublicationTime
        {
            get { return _publicationTime; }
            set
            {
                PutTag(value, _publicationTime);
                _publicationTime = value;
            }
        }

        public ImprintTag PublicationHash
        {
            get { return _publicationHash; }
            set
            {
                PutTag(value, _publicationHash);
                _publicationHash = value;
            }
        }

        public PublicationData(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Value.Count; i++)
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


        protected override void CheckStructure()
        {
            for (int i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x2:
                    case 0x4:
                        break;
                    default:
                        throw new InvalidTlvStructureException("Invalid tag", Value[i]);
                }
            }
        }
    }
}
