using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{

    /// <summary>
    /// Signature data TLV element
    /// </summary>
    public sealed class SignatureData : CompositeTag
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
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid signature data type: " + Type);
            }

            int signatureTypeCount = 0;
            int signatureValueCount = 0;
            int certificateIdCount = 0;
            int certificateRepositoryUriCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case SignatureTypeTagType:
                        _signatureType = new StringTag(this[i]);
                        this[i] = _signatureType;
                        signatureTypeCount++;
                        break;
                    case SignatureValueTagType:
                        _signatureValue = new RawTag(this[i]);
                        this[i] = _signatureValue;
                        signatureValueCount++;
                        break;
                    case CertificateIdTagType:
                        _certificateId = new RawTag(this[i]);
                        this[i] = _certificateId;
                        certificateIdCount++;
                        break;
                    case CertificateRepositoryUriTagType:
                        _certificateRepositoryUri = new StringTag(this[i]);
                        this[i] = _certificateRepositoryUri;
                        certificateRepositoryUriCount++;
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
                        break;
                }
            }


            if (signatureTypeCount != 1)
            {
                throw new InvalidTlvStructureException("Only one signature type must exist in signature data");
            }

            if (signatureValueCount != 1)
            {
                throw new InvalidTlvStructureException("Only one signature value must exist in signature data");
            }

            if (certificateIdCount != 1)
            {
                throw new InvalidTlvStructureException("Only one certificate id must exist in signature data");
            }

            if (certificateRepositoryUriCount > 1)
            {
                throw new InvalidTlvStructureException("Only one certificate repository uri is allowed in signature data");
            }
        }
    }
}