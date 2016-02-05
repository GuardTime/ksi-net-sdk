using Guardtime.KSI.Parser;
using Guardtime.KSI.Trust;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publications file interface.
    /// </summary>
    public interface IPublicationsFile : ITlvTag, IKsiTrustProvider
    {
        /// <summary>
        ///     Get nearest publication record subsequent to given time.
        /// </summary>
        /// <param name="time">time</param>
        /// <returns>publication record closest to time</returns>
        PublicationRecordInPublicationFile GetNearestPublicationRecord(ulong time);

        /// <summary>
        ///     Get latest publication record.
        /// </summary>
        /// <returns>publication record</returns>
        PublicationRecordInPublicationFile GetLatestPublication();
    }
}