﻿/*
 * Copyright 2013-2018 Guardtime, Inc.
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
        /// Aggregator configuration changed event
        /// </summary>
        event EventHandler<AggregatorConfigChangedEventArgs> AggregatorConfigChanged;

        /// <summary>
        /// Extender configuration changed event
        /// </summary>
        event EventHandler<ExtenderConfigChangedEventArgs> ExtenderConfigChanged;

        /// <summary>
        ///     Create signature with given data hash (sync).
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        /// <returns>KSI signature</returns>
        IKsiSignature Sign(DataHash hash, uint level = 0);

        /// <summary>
        ///     Begin create signature with given data hash (async).
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginSign(DataHash hash, AsyncCallback callback, object asyncState);

        /// <summary>
        ///     Begin create signature with given data hash (async).
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginSign(DataHash hash, uint level, AsyncCallback callback, object asyncState);

        /// <summary>
        /// Get sign request response payload (async).
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>Request response payload</returns>
        SignRequestResponsePayload GetSignResponsePayload(IAsyncResult asyncResult);

        /// <summary>
        ///     End create signature (async)
        /// </summary>
        /// <param name="asyncResult">async result</param>
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
        /// <param name="callback">callback when aggregator configuration request is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginGetAggregatorConfig(AsyncCallback callback, object asyncState);

        /// <summary>
        /// End get additional aggregator configuration data (async)
        /// </summary>
        /// <param name="asyncResult"></param>
        /// <returns>Aggregator configuration data</returns>
        AggregatorConfig EndGetAggregatorConfig(IAsyncResult asyncResult);

        /// <summary>
        ///     Extend to latest publication (sync).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <returns>extended calendar hash chain</returns>
        CalendarHashChain Extend(ulong aggregationTime);

        /// <summary>
        ///     Extend to given publication (sync).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        /// <returns>extended calendar hash chain</returns>
        CalendarHashChain Extend(ulong aggregationTime, ulong publicationTime);

        /// <summary>
        ///     Begin extend to latest publication (async).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="callback">callback when extending request is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginExtend(ulong aggregationTime, AsyncCallback callback, object asyncState);

        /// <summary>
        ///     Begin extend to given publication (async).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        /// <param name="callback">callback when extending request is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginExtend(ulong aggregationTime, ulong publicationTime, AsyncCallback callback, object asyncState);

        /// <summary>
        ///     End extend (async).
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>extended calendar hash chain</returns>
        CalendarHashChain EndExtend(IAsyncResult asyncResult);

        /// <summary>
        /// Get additional extender configuration data (sync)
        /// </summary>
        /// <returns>Extender configuration data</returns>
        ExtenderConfig GetExtenderConfig();

        /// <summary>
        /// Begin get additional extender configuration data (async)
        /// </summary>
        /// <param name="callback">callback when extender configuration request is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginGetExtenderConfig(AsyncCallback callback, object asyncState);

        /// <summary>
        /// End get additional extender configuration data (async)
        /// </summary>
        /// <param name="asyncResult"></param>
        /// <returns>Extender configuration data</returns>
        ExtenderConfig EndGetExtenderConfig(IAsyncResult asyncResult);

        /// <summary>
        ///     Get publications file (sync).
        /// </summary>
        /// <returns>Publications file</returns>
        IPublicationsFile GetPublicationsFile();

        /// <summary>
        ///     Begin get publications file (async).
        /// </summary>
        /// <param name="callback">callback when publications file is downloaded</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState);

        /// <summary>
        ///     End get publications file (async).
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>publications file</returns>
        IPublicationsFile EndGetPublicationsFile(IAsyncResult asyncResult);

        /// <summary>
        /// Aggregator address
        /// </summary>
        string AggregatorAddress { get; }

        /// <summary>
        /// Extender address
        /// </summary>
        string ExtenderAddress { get; }

        /// <summary>
        /// Publications file url
        /// </summary>
        string PublicationsFileAddress { get; }
    }
}