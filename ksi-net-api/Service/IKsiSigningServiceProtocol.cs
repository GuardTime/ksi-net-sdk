using System;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// KSI service protocol interface.
    /// </summary>
    public interface IKsiSigningServiceProtocol
    {
        /// <summary>
        /// Async begin create signature.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="callback">callback when response is ready</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginSign(byte[] data, AsyncCallback callback, object asyncState);
        /// <summary>
        /// Async end create signature.
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>aggregation response bytes</returns>
        byte[] EndSign(IAsyncResult asyncResult);
    }
}