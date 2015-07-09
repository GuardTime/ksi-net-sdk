using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    /// Calendar authentication record TLV element
    /// </summary>
    public class CalendarAuthenticationRecord : CompositeTag
    {
        // TODO: Better name
        /// <summary>
        /// Calendar authentication record tag type
        /// </summary>
        public const uint TagType = 0x805;

        private readonly PublicationData _publicationData;
        private readonly SignatureData _signatureData;

        /// <summary>
        /// Create new calendar authentication record TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public CalendarAuthenticationRecord(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case PublicationData.TagType:
                        _publicationData = new PublicationData(this[i]);
                        this[i] = _publicationData;
                        break;
                    case SignatureData.TagType:
                        _signatureData = new SignatureData(this[i]);
                        this[i] = _signatureData;
                        break;
                }
            }
        }

        /// <summary>
        /// Check TLV structure.
        /// </summary>
        protected override void CheckStructure()
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid calendar authentication record type: " + Type);
            }

            uint[] tags = new uint[2];

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case PublicationData.TagType:
                        tags[0]++;
                        break;
                    case SignatureData.TagType:
                        tags[1]++;
                        break;
                    default:
                        throw new InvalidTlvStructureException("Invalid tag", this[i]);
                }
            }

            if (tags[0] != 1)
            {
                throw new InvalidTlvStructureException("Only one publication data must exist in calendar authentication record");
            }

            if (tags[1] != 1)
            {
                throw new InvalidTlvStructureException("Only one signature data must exist in calendar authentication record");
            }
        }
    }
}