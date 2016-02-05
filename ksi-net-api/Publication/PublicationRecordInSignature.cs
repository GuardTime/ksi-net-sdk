using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publication record TLV element to be used in signature.
    /// </summary>
    public sealed class PublicationRecordInSignature : PublicationRecord
    {
        /// <summary>
        ///     Create new publication record TLV element to be used in signature.
        /// </summary>
        /// <param name="tag">TLV element the publication record will be created from</param>
        public PublicationRecordInSignature(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.PublicationRecord.TagTypeInSignature)
            {
                throw new TlvException("Invalid publication record type(" + Type + ").");
            }
        }

        /// <summary>
        /// Create new publication record TLV element to be used in signature.
        /// </summary>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">child TLV element list</param>
        public PublicationRecordInSignature(bool nonCritical, bool forward, ITlvTag[] value) : base(Constants.PublicationRecord.TagTypeInSignature, nonCritical, forward, value)
        {
        }
    }
}