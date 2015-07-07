using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class PublicationData : CompositeTag
    {
        // TODO: Better name
        public const uint TagType = 0x10;
        private const uint PublicationTimeTagType = 0x2;
        private const uint PublicationHashTagType = 0x4;

        private readonly IntegerTag _publicationTime;
        private readonly ImprintTag _publicationHash;

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
                    case PublicationTimeTagType:
                        _publicationTime = new IntegerTag(this[i]);
                        this[i] = _publicationTime;
                        break;
                    case PublicationHashTagType:
                        _publicationHash = new ImprintTag(this[i]);
                        this[i] = _publicationHash;
                        break;
                }
            }
        }


        protected override void CheckStructure()
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid publication record type: " + Type);
            }

            uint[] tags = new uint[2];

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case PublicationTimeTagType:
                        tags[0]++;
                        break;
                    case PublicationHashTagType:
                        tags[1]++;
                        break;
                    default:
                        throw new InvalidTlvStructureException("Invalid tag", this[i]);
                }
            }

            if (tags[0] != 1)
            {
                throw new InvalidTlvStructureException("Only one publication time must exist in publication data");
            }

            if (tags[1] != 1)
            {
                throw new InvalidTlvStructureException("Only one publication hash must exist in publication data");
            }

        }
    }
}
