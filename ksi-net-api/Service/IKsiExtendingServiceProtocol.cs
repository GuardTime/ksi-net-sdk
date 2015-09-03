using System;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// KSI service protocol interface.
    /// </summary>
    public interface IKsiExtendingServiceProtocol
    {
        /// <summary>
        /// Async begin extend signature.
        /// </summary>
        /// <param name="data">extension request bytes</param>
        /// <param name="callback">callback when response is ready</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginExtend(byte[] data, AsyncCallback callback, object asyncState);
        /// <summary>
        /// Async end extend signature.
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>extension response bytes</returns>
        byte[] EndExtend(IAsyncResult asyncResult);
    }
}