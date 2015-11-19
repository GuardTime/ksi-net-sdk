using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publications file header TLV element.
    /// </summary>
    public sealed class PublicationsFileHeader : CompositeTag
    {
        private readonly IntegerTag _creationTime;
        private readonly StringTag _repUri;
        private readonly IntegerTag _version;

        /// <summary>
        ///     Create publications file header TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public PublicationsFileHeader(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.PublicationsFileHeader.TagType)
            {
                throw new TlvException("Invalid certificate record type(" + Type + ").");
            }

            int versionCount = 0;
            int creationTimeCount = 0;
            int repUriCount = 0;

            foreach (ITlvTag childTag in this)
            {
                switch (childTag.Type)
                {
                    case Constants.PublicationsFileHeader.VersionTagType:
                        _version = new IntegerTag(childTag);
                        versionCount++;
                        break;
                    case Constants.PublicationsFileHeader.CreationTimeTagType:
                        _creationTime = new IntegerTag(childTag.Type, childTag.NonCritical, childTag.Forward,
                            Util.DecodeUnsignedLong(childTag.EncodeValue(), 0, childTag.EncodeValue().Length));
                        creationTimeCount++;
                        break;
                    case Constants.PublicationsFileHeader.RepUriTagType:
                        _repUri = new StringTag(childTag);
                        repUriCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (versionCount != 1)
            {
                throw new TlvException("Only one version must exist in publications file header.");
            }

            if (creationTimeCount != 1)
            {
                throw new TlvException("Only one creation time must exist in publications file header.");
            }

            if (repUriCount > 1)
            {
                throw new TlvException("Only one repository uri is allowed in publications file header.");
            }
        }

        /// <summary>
        ///     Get publications file creation time.
        /// </summary>
        public ulong CreationTime => _creationTime.Value;

        /// <summary>
        ///     Get publications file repository uri if it exists.
        /// </summary>
        public string RepUri => _repUri?.Value;

        /// <summary>
        ///     Get publications file version.
        /// </summary>
        public ulong Version => _version.Value;
    }
}