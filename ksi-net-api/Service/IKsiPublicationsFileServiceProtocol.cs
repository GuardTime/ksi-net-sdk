using System;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// KSI service protocol interface.
    /// </summary>
    public interface IKsiPublicationsFileServiceProtocol
    {
        /// <summary>
        /// Async begin get publications file.
        /// </summary>
        /// <param name="callback">callback when publications file is finished downloading</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState);
        /// <summary>
        /// Async end get publications file.
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>publications file bytes</returns>
        byte[] EndGetPublicationsFile(IAsyncResult asyncResult);
    }
}