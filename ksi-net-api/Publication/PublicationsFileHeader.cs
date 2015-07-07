using System;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Publication
{
    internal class PublicationsFileHeader : CompositeTag
    {
        // TODO: Better name
        public const uint TagType = 0x701;
        private const uint VersionTagType = 0x1;
        private const uint CreationTimeTagType = 0x2;
        private const uint RepUriTagType = 0x3;

        private readonly IntegerTag _version;
        private readonly IntegerTag _creationTime;
        private readonly StringTag _repUri;

        // TODO: Should structure be checked right away?
        public DateTime? CreationTime
        {
            
            get { return _creationTime; }
        }

        public string RepUri
        {
            get { return _repUri != null ? _repUri.Value : null; }
        }

        public PublicationsFileHeader(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case VersionTagType:
                        _version = new IntegerTag(this[i]);
                        this[i] = _version;
                        break;
                    case CreationTimeTagType:
                        // TODO: temporary solution to publication file creationtime since it is too large (max value can be 10000 years in c#)
                        _creationTime = new IntegerTag(this[i].Type, this[i].NonCritical, this[i].Forward, Util.DecodeUnsignedLong(this[i].EncodeValue(), 0, this[i].EncodeValue().Length) / 1000);
                        this[i] = _creationTime;
                        break;
                    case RepUriTagType:
                        _repUri = new StringTag(this[i]);
                        this[i] = _repUri;
                        break;
                }
            }
        }

        protected override void CheckStructure()
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid publication file header type: " + Type);
            }

            uint[] tags = new uint[3];

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case VersionTagType:
                        tags[0]++;
                        break;
                    case CreationTimeTagType:
                        tags[1]++;
                        break;
                    case RepUriTagType:
                        tags[2]++;
                        break;
                    default:
                        throw new InvalidTlvStructureException("Invalid tag", this[i]);
                }
            }

            if (tags[0] != 1)
            {
                throw new InvalidTlvStructureException("Only one version must exist in publications file header");
            }

            if (tags[1] != 1)
            {
                throw new InvalidTlvStructureException("Only one creation time must exist in publications file header");
            }

            if (tags[2] > 1)
            {
                throw new InvalidTlvStructureException("Only one repository uri is allowed in publications file header");
            }
        }
    }
}