/*
 * Copyright 2013-2017 Guardtime, Inc.
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
    ///     Service protocol interface for making KSI signing request.
    /// </summary>
    public interface IKsiSigningServiceProtocol
    {
        /// <summary>
        ///     Begin signing request.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when response is ready</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginSign(byte[] data, ulong requestId, AsyncCallback callback, object asyncState);

        /// <summary>
        ///     End signing request.
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>response bytes</returns>
        byte[] EndSign(IAsyncResult asyncResult);

        /// <summary>
        ///     Begin aggregator configuration request.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when response is ready</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginGetAggregatorConfig(byte[] data, ulong requestId, AsyncCallback callback, object asyncState);

        /// <summary>
        ///     End aggregator configuration request.
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>response bytes</returns>
        byte[] EndGetAggregatorConfig(IAsyncResult asyncResult);

        /// <summary>
        /// Aggregator address (url or ip)
        /// </summary>
        string AggregatorAddress { get; }
    }
}