using System;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    /// Publications file header TLV element.
    /// </summary>
    public sealed class PublicationsFileHeader : CompositeTag
    {
        /// <summary>
        /// Publications file header TLV type.
        /// </summary>
        public const uint TagType = 0x701;
        private const uint VersionTagType = 0x1;
        private const uint CreationTimeTagType = 0x2;
        private const uint RepUriTagType = 0x3;

        private readonly IntegerTag _version;
        private readonly IntegerTag _creationTime;
        private readonly StringTag _repUri;

        /// <summary>
        /// Get publications file creation time.
        /// </summary>
        public DateTime? CreationTime
        {
            
            get { return _creationTime == null ? (DateTime?)null : Util.ConvertUnixTimeToDateTime(_creationTime.Value); }
        }

        /// <summary>
        /// Get publications file repository uri.
        /// </summary>
        public string RepUri
        {
            get { return _repUri != null ? _repUri.Value : null; }
        }

        /// <summary>
        /// Create publications file header TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public PublicationsFileHeader(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid publication file header type: " + Type);
            }

            int versionCount = 0;
            int creationTimeCount = 0;
            int repUriCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case VersionTagType:
                        _version = new IntegerTag(this[i]);
                        this[i] = _version;
                        versionCount++;
                        break;
                    case CreationTimeTagType:
                        // TODO: temporary solution to publication file creationtime since it is too large (max value can be 10000 years in c#)
                        _creationTime = new IntegerTag(this[i].Type, this[i].NonCritical, this[i].Forward, Util.DecodeUnsignedLong(this[i].EncodeValue(), 0, this[i].EncodeValue().Length) / 1000);
                        this[i] = _creationTime;
                        creationTimeCount++;
                        break;
                    case RepUriTagType:
                        _repUri = new StringTag(this[i]);
                        this[i] = _repUri;
                        repUriCount++;
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
                        break;
                }
            }

            if (versionCount != 1)
            {
                throw new InvalidTlvStructureException("Only one version must exist in publications file header");
            }

            if (creationTimeCount != 1)
            {
                throw new InvalidTlvStructureException("Only one creation time must exist in publications file header");
            }

            if (repUriCount > 1)
            {
                throw new InvalidTlvStructureException("Only one repository uri is allowed in publications file header");
            }
        }
    }
}