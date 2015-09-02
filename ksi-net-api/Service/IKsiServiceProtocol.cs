using System;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// KSI service protocol interface.
    /// </summary>
    public interface IKsiServiceProtocol
    {
        /// <summary>
        /// Async begin create signature.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="callback">callback when response is ready</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginCreateSignature(byte[] data, AsyncCallback callback, object asyncState);
        /// <summary>
        /// Async end create signature.
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>aggregation response bytes</returns>
        byte[] EndCreateSignature(IAsyncResult asyncResult);
        /// <summary>
        /// Async begin extend signature.
        /// </summary>
        /// <param name="data">extension request bytes</param>
        /// <param name="callback">callback when response is ready</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginExtendSignature(byte[] data, AsyncCallback callback, object asyncState);
        /// <summary>
        /// Async end extend signature.
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>extension response bytes</returns>
        byte[] EndExtendSignature(IAsyncResult asyncResult);
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