/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

using System;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     KSI service protocol interface.
    /// </summary>
    public interface IKsiSigningServiceProtocol
    {
        /// <summary>
        ///     Async begin create signature.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when response is ready</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginSign(byte[] data, ulong requestId, AsyncCallback callback, object asyncState);

        /// <summary>
        ///     Async end create signature.
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>aggregation response bytes</returns>
        byte[] EndSign(IAsyncResult asyncResult);
    }
}