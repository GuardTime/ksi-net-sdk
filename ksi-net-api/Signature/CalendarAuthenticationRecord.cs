using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     Calendar authentication record TLV element
    /// </summary>
    public sealed class CalendarAuthenticationRecord : CompositeTag
    {
        /// <summary>
        ///     Calendar authentication record TLV type
        /// </summary>
        public const uint TagType = 0x805;

        private readonly PublicationData _publicationData;
        private readonly SignatureData _signatureData;

        /// <summary>
        ///     Create new calendar authentication record TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public CalendarAuthenticationRecord(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new TlvException("Invalid calendar authentication record type(" + Type + ").");
            }

            int publicationDataCount = 0;
            int signatureDataCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case PublicationData.TagType:
                        _publicationData = new PublicationData(this[i]);
                        this[i] = _publicationData;
                        publicationDataCount++;
                        break;
                    case SignatureData.TagType:
                        _signatureData = new SignatureData(this[i]);
                        this[i] = _signatureData;
                        signatureDataCount++;
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
                        break;
                }
            }

            if (publicationDataCount != 1)
            {
                throw new TlvException(
                    "Only one publication data must exist in calendar authentication record.");
            }

            if (signatureDataCount != 1)
            {
                throw new TlvException(
                    "Only one signature data must exist in calendar authentication record.");
            }
        }

        /// <summary>
        ///     Get publication data.
        /// </summary>
        public PublicationData PublicationData
        {
            get { return _publicationData; }
        }

        /// <summary>
        ///     Get signature data.
        /// </summary>
        public SignatureData SignatureData
        {
            get { return _signatureData; }
        }
    }
}