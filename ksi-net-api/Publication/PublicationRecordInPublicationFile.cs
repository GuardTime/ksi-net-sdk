using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publication record TLV element in publication file.
    /// </summary>
    public sealed class PublicationRecordInPublicationFile : PublicationRecord
    {
        /// <summary>
        ///     Create new publication record TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public PublicationRecordInPublicationFile(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.PublicationRecord.TagTypeInPublicationsFile)
            {
                throw new TlvException("Invalid publication record type(" + Type + ").");
            }
        }

        /// <summary>
        /// Convert current publication record to PublicationRecordInSignature
        /// </summary>
        /// <returns></returns>
        public PublicationRecordInSignature ConvertToPublicationRecordInSignature()
        {
            ITlvTag[] values = new ITlvTag[Count];
            for (int i = 0; i < Count; i++)
            {
                values[i] = this[i];
            }
            return new PublicationRecordInSignature(NonCritical, Forward, values);
        }
    }
}