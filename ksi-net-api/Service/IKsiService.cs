
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using System;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// KSI service interface.
    /// </summary>
    public interface IKsiService
    {
        /// <summary>
        /// Sync create signature with given data hash.
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <returns>KSI signature</returns>
        KsiSignature Sign(DataHash hash);

        /// <summary>
        /// Async begin create signature with given data hash.
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginSign(DataHash hash, AsyncCallback callback, object asyncState);
        /// <summary>
        /// Async end create signature.
        /// </summary>
        /// <param name="asyncResult">async result status</param>
        /// <returns>KSI signature</returns>
        KsiSignature EndSign(IAsyncResult asyncResult);
        /// <summary>
        /// Sync extend signature to latest publication.
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <returns>extended calendar hash chain</returns>
        CalendarHashChain Extend(ulong aggregationTime);
        /// <summary>
        /// Sync extend signature to given publication.
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        /// <returns>extended calendar hash chain</returns>
        CalendarHashChain Extend(ulong aggregationTime, ulong publicationTime);
        /// <summary>
        /// Async begin extend signature to latest publication.
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginExtend(ulong aggregationTime, AsyncCallback callback, object asyncState);
        /// <summary>
        /// Async begin extend signature to given publication.
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginExtend(ulong aggregationTime, ulong publicationTime, AsyncCallback callback, object asyncState);
        /// <summary>
        /// Async end extend signature.
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>extended calendar hash chain</returns>
        CalendarHashChain EndExtend(IAsyncResult asyncResult);
        /// <summary>
        /// Sync get publications file.
        /// </summary>
        /// <returns>Publications file</returns>
        PublicationsFile GetPublicationsFile();
        /// <summary>
        /// Async begin get publications file.
        /// </summary>
        /// <param name="callback">callback when publications file is downloaded</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState);
        /// <summary>
        /// Async end get publications file.
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>publications file</returns>
        PublicationsFile EndGetPublicationsFile(IAsyncResult asyncResult);
    }
}
