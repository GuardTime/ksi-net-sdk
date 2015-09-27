using Guardtime.KSI.Trust;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publications file interface.
    /// </summary>
    public interface IPublicationsFile : IKsiTrustProvider
    {
        /// <summary>
        ///     Get neared publication record to time.
        /// </summary>
        /// <param name="time">publication time</param>
        /// <returns>publication record closest to time</returns>
        PublicationRecord GetNearestPublicationRecord(ulong time);

        /// <summary>
        ///     Get latest publication record.
        /// </summary>
        /// <returns>publication record</returns>
        PublicationRecord GetLatestPublication();
    }
}