using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publication record TLV element.
    /// </summary>
    public sealed class PublicationRecord : CompositeTag
    {
        /// <summary>
        ///     Create new publication record TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public PublicationRecord(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.PublicationRecord.TagTypeSignature && Type != Constants.PublicationRecord.TagTypePublication)
            {
                throw new TlvException("Invalid publication record type(" + Type + ").");
            }

            int publicationDataCount = 0;

            for (int i = 0; i < Count; i++)
            {
                StringTag listTag;

                switch (this[i].Type)
                {
                    case Constants.PublicationData.TagType:
                        PublicationData = new PublicationData(this[i]);
                        publicationDataCount++;
                        break;
                    case Constants.PublicationRecord.PublicationReferencesTagType:
                        listTag = new StringTag(this[i]);
                        PublicationReferences.Add(listTag);
                        break;
                    case Constants.PublicationRecord.PublicationRepositoryUriTagType:
                        listTag = new StringTag(this[i]);
                        PubRepUri.Add(listTag);
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
                        break;
                }
            }

            if (publicationDataCount != 1)
            {
                throw new TlvException("Only one publication data is allowed in publication record.");
            }
        }

        /// <summary>
        ///     Get publication data.
        /// </summary>
        public PublicationData PublicationData { get; }

        /// <summary>
        ///     Get publication references.
        /// </summary>
        public List<StringTag> PublicationReferences { get; } = new List<StringTag>();

        /// <summary>
        ///     Get publication repository uri.
        /// </summary>
        public List<StringTag> PubRepUri { get; } = new List<StringTag>();
    }
}