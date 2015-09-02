
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
        KsiSignature CreateSignature(DataHash hash);

        /// <summary>
        /// Async begin create signature with given data hash.
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginCreateSignature(DataHash hash, AsyncCallback callback, object asyncState);
        /// <summary>
        /// Async end create signature.
        /// </summary>
        /// <param name="asyncResult">async result status</param>
        /// <returns>KSI signature</returns>
        KsiSignature EndCreateSignature(IAsyncResult asyncResult);
        /// <summary>
        /// Sync extend signature to latest publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <returns>extended KSI signature</returns>
        KsiSignature ExtendSignature(KsiSignature signature);
        /// <summary>
        /// Sync extend signature to given publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="publicationRecord">publication record</param>
        /// <returns>extended KSI signature</returns>
        KsiSignature ExtendSignature(KsiSignature signature, PublicationRecord publicationRecord);
        /// <summary>
        /// Async begin extend signature to latest publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginExtendSignature(KsiSignature signature, AsyncCallback callback, object asyncState);
        /// <summary>
        /// Async begin extend signature to given publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="publicationRecord">publication record</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginExtendSignature(KsiSignature signature, PublicationRecord publicationRecord, AsyncCallback callback, object asyncState);
        /// <summary>
        /// Async end extend signature.
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>extended KSI signature</returns>
        KsiSignature EndExtendSignature(IAsyncResult asyncResult);
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
