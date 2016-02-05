using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publication record TLV element.
    /// </summary>
    public abstract class PublicationRecord : CompositeTag
    {
        /// <summary>
        ///     Create new publication record TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected PublicationRecord(ITlvTag tag) : base(tag)
        {
            int publicationDataCount = 0;

            foreach (ITlvTag childTag in this)
            {
                switch (childTag.Type)
                {
                    case Constants.PublicationData.TagType:
                        PublicationData = new PublicationData(childTag);
                        publicationDataCount++;
                        break;
                    case Constants.PublicationRecord.PublicationReferencesTagType:
                        PublicationReferences.Add(new StringTag(childTag));
                        break;
                    case Constants.PublicationRecord.PublicationRepositoryUriTagType:
                        RepositoryUri.Add(new StringTag(childTag));
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (publicationDataCount != 1)
            {
                throw new TlvException("Only one publication data is allowed in publication record.");
            }
        }

        protected PublicationRecord(uint type, bool nonCritical, bool forward, ITlvTag[] value) : base(type, nonCritical, forward, value)
        {
        }

        /// <summary>
        ///     Get publication data.
        /// </summary>
        public PublicationData PublicationData { get; }

        /// <summary>
        ///     Get publication references.
        /// </summary>
        public IList<StringTag> PublicationReferences { get; } = new List<StringTag>();

        /// <summary>
        ///     Get publication repository uri.
        /// </summary>
        public IList<StringTag> RepositoryUri { get; } = new List<StringTag>();
    }
}