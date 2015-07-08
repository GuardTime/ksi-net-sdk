using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{

    /// <summary>
    /// Signature data TLV element
    /// </summary>
    public class SignatureData : CompositeTag
    {
        // TODO: Better name
        /// <summary>
        /// Signature data tag type
        /// </summary>
        public const uint TagType = 0xb;
        private const uint SignatureTypeTagType = 0x1;
        private const uint SignatureValueTagType = 0x2;
        private const uint CertificateIdTagType = 0x3;
        private const uint CertificateRepositoryUriTagType = 0x4;

        private readonly StringTag _signatureType;
        private readonly RawTag _signatureValue;
        private readonly RawTag _certificateId;
        private readonly StringTag _certificateRepositoryUri;

        /// <summary>
        /// Create new signature data TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        public SignatureData(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case SignatureTypeTagType:
                        _signatureType = new StringTag(this[i]);
                        this[i] = _signatureType;
                        break;
                    case SignatureValueTagType:
                        _signatureValue = new RawTag(this[i]);
                        this[i] = _signatureValue;
                        break;
                    case CertificateIdTagType:
                        _certificateId = new RawTag(this[i]);
                        this[i] = _certificateId;
                        break;
                    case CertificateRepositoryUriTagType:
                        _certificateRepositoryUri = new StringTag(this[i]);
                        this[i] = _certificateRepositoryUri;
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
                throw new InvalidTlvStructureException("Invalid signature data type: " + Type);
            }

            uint[] tags = new uint[4];

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case SignatureTypeTagType:
                        tags[0]++;
                        break;
                    case SignatureValueTagType:
                        tags[1]++;
                        break;
                    case CertificateIdTagType:
                        tags[2]++;
                        break;
                    case CertificateRepositoryUriTagType:
                        tags[3]++;
                        break;
                    default:
                        throw new InvalidTlvStructureException("Invalid tag", this[i]);
                }
            }

            if (tags[0] != 1)
            {
                throw new InvalidTlvStructureException("Only one signature type must exist in signature data");
            }

            if (tags[1] != 1)
            {
                throw new InvalidTlvStructureException("Only one signature value must exist in signature data");
            }

            if (tags[2] != 1)
            {
                throw new InvalidTlvStructureException("Only one certificate id must exist in signature data");
            }

            if (tags[3] > 1)
            {
                throw new InvalidTlvStructureException("Only one certificate repository uri is allowed in signature data");
            }
        }
    }
}