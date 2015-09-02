using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using System.Collections.Generic;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    /// Publication data TLV element.
    /// </summary>
    public sealed class PublicationData : CompositeTag
    {
        // TODO: Better name
        /// <summary>
        /// Publication data tag type.
        /// </summary>
        public const uint TagType = 0x10;
        private const uint PublicationTimeTagType = 0x2;
        private const uint PublicationHashTagType = 0x4;

        private readonly IntegerTag _publicationTime;
        private readonly ImprintTag _publicationHash;

        /// <summary>
        /// Get publication time.
        /// </summary>
        public IntegerTag PublicationTime
        {
            get { return _publicationTime; }
        }

        /// <summary>
        /// Get publication hash .
        /// </summary>
        public ImprintTag PublicationHash
        {
            get { return _publicationHash; }
        }

        /// <summary>
        /// Create new publication data TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public PublicationData(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid publication record type: " + Type);
            }

            int publicationTimeCount = 0;
            int publicationHashCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case PublicationTimeTagType:
                        _publicationTime = new IntegerTag(this[i]);
                        this[i] = _publicationTime;
                        publicationTimeCount++;
                        break;
                    case PublicationHashTagType:
                        _publicationHash = new ImprintTag(this[i]);
                        this[i] = _publicationHash;
                        publicationHashCount++;
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
                        break;
                }
            }

            if (publicationTimeCount != 1)
            {
                throw new InvalidTlvStructureException("Only one publication time must exist in publication data");
            }

            if (publicationHashCount != 1)
            {
                throw new InvalidTlvStructureException("Only one publication hash must exist in publication data");
            }
        }

        /// <summary>
        /// Create new publication data TLV element from publication time and publication hash.
        /// </summary>
        /// <param name="publicationTime">publication time</param>
        /// <param name="publicationHash">publication hash</param>
        public PublicationData(ulong publicationTime, DataHash publicationHash) : base(TagType, false, true, new List<TlvTag>())
        {
            _publicationTime = new IntegerTag(PublicationTimeTagType, false, false, publicationTime);
            AddTag(_publicationTime);
            _publicationHash = new ImprintTag(PublicationHashTagType, false, false, publicationHash);
            AddTag(_publicationHash);
        }
    }
}
