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
        }

        public ImprintTag PublicationHash
        {
            get { return _publicationHash; }
        }

        public PublicationData(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case 0x2:
                        _publicationTime = new IntegerTag(this[i]);
                        this[i] = _publicationTime;
                        break;
                    case 0x4:
                        _publicationHash = new ImprintTag(this[i]);
                        this[i] = _publicationHash;
                        break;
                }
            }
        }


        protected override void CheckStructure()
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case 0x2:
                    case 0x4:
                        break;
                    default:
                        throw new InvalidTlvStructureException("Invalid tag", this[i]);
                }
            }
        }
    }
}
