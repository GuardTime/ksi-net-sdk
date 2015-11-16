using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     Signature data TLV element
    /// </summary>
    public sealed class SignatureData : CompositeTag
    {
        /// <summary>
        ///     Signature data tag type
        /// </summary>
        public const uint TagType = 0xb;

        private const uint SignatureTypeTagType = 0x1;
        private const uint SignatureValueTagType = 0x2;
        private const uint CertificateIdTagType = 0x3;
        private const uint CertificateRepositoryUriTagType = 0x4;
        private readonly RawTag _certificateId;
        private readonly StringTag _certificateRepositoryUri;

        private readonly StringTag _signatureType;
        private readonly RawTag _signatureValue;

        /// <summary>
        ///     Create new signature data TLV element from TLV element
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public SignatureData(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new TlvException("Invalid signature data type(" + Type + ").");
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
                        signatureTypeCount++;
                        break;
                    case SignatureValueTagType:
                        _signatureValue = new RawTag(this[i]);
                        signatureValueCount++;
                        break;
                    case CertificateIdTagType:
                        _certificateId = new RawTag(this[i]);
                        certificateIdCount++;
                        break;
                    case CertificateRepositoryUriTagType:
                        _certificateRepositoryUri = new StringTag(this[i]);
                        certificateRepositoryUriCount++;
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
                        break;
                }
            }


            if (signatureTypeCount != 1)
            {
                throw new TlvException("Only one signature type must exist in signature data.");
            }

            if (signatureValueCount != 1)
            {
                throw new TlvException("Only one signature value must exist in signature data.");
            }

            if (certificateIdCount != 1)
            {
                throw new TlvException("Only one certificate id must exist in signature data.");
            }

            if (certificateRepositoryUriCount > 1)
            {
                throw new TlvException(
                    "Only one certificate repository uri is allowed in signature data.");
            }
        }

        /// <summary>
        ///     Get certificate ID.
        /// </summary>
        public byte[] CertificateId
        {
            get { return _certificateId.Value; }
        }

        /// <summary>
        ///     Get signature value.
        /// </summary>
        public byte[] SignatureValue
        {
            get { return _signatureValue.Value; }
        }

        /// <summary>
        ///     Get signature type.
        /// </summary>
        public string SignatureType
        {
            get { return _signatureType.Value; }
        }

        /// <summary>
        ///     Get certificate repository URI if it exists.
        /// </summary>
        public string CertificateRepositoryUri
        {
            get { return _certificateRepositoryUri == null ? null : _certificateRepositoryUri.Value; }
        }
    }
}