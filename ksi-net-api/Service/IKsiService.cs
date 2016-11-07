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
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     KSI service interface.
    /// </summary>
    public interface IKsiService
    {
        /// <summary>
        ///     Sync create signature with given data hash.
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <returns>KSI signature</returns>
        IKsiSignature Sign(DataHash hash);

        /// <summary>
        ///     Create signature with given data hash (sync)
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        /// <returns>KSI signature</returns>
        IKsiSignature Sign(DataHash hash, uint level);

        /// <summary>
        ///     Begin create signature with given data hash (async).
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginSign(DataHash hash, AsyncCallback callback, object asyncState);

        /// <summary>
        ///     Begin create signature with given data hash (async).
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginSign(DataHash hash, uint level, AsyncCallback callback, object asyncState);

        /// <summary>
        ///     End create signature (async)
        /// </summary>
        /// <param name="asyncResult">async result status</param>
        /// <returns>KSI signature</returns>
        IKsiSignature EndSign(IAsyncResult asyncResult);

        /// <summary>
        /// Get additional aggregator configuration data (sync)
        /// </summary>
        /// <returns>Aggregator configuration data</returns>
        AggregatorConfig GetAggregatorConfig();

        /// <summary>
        /// Begin get additional aggregator configuration data (async)
        /// </summary>
        /// <param name="callback"></param>
        /// <param name="asyncState"></param>
        /// <returns>async result</returns>
        IAsyncResult BeginGetAggregatorConfig(AsyncCallback callback, object asyncState);

        /// <summary>
        /// End get additional aggregator configuration data (async)
        /// </summary>
        /// <param name="asyncResult"></param>
        /// <returns>Aggregator configuration data</returns>
        AggregatorConfig EndGetAggregatorConfig(IAsyncResult asyncResult);

        /// <summary>
        ///     Extend signature to latest publication (sync).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <returns>extended calendar hash chain</returns>
        CalendarHashChain Extend(ulong aggregationTime);

        /// <summary>
        ///     Extend signature to given publication (sync).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        /// <returns>extended calendar hash chain</returns>
        CalendarHashChain Extend(ulong aggregationTime, ulong publicationTime);

        /// <summary>
        ///     Begin extend signature to latest publication (async).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginExtend(ulong aggregationTime, AsyncCallback callback, object asyncState);

        /// <summary>
        ///     Begin extend signature to given publication (async).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginExtend(ulong aggregationTime, ulong publicationTime, AsyncCallback callback, object asyncState);

        /// <summary>
        ///     End extend signature (async).
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>extended calendar hash chain</returns>
        CalendarHashChain EndExtend(IAsyncResult asyncResult);

        /// <summary>
        ///     Get publications file (sync).
        /// </summary>
        /// <returns>Publications file</returns>
        IPublicationsFile GetPublicationsFile();

        /// <summary>
        ///     Begin get publications file (async).
        /// </summary>
        /// <param name="callback">callback when publications file is downloaded</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState);

        /// <summary>
        ///     End get publications file (async).
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>publications file</returns>
        IPublicationsFile EndGetPublicationsFile(IAsyncResult asyncResult);
    }
}