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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using NLog;

namespace Guardtime.KSI.Service.HighAvailability
{
    /// <summary>
    /// High availability KSI service. Combines max 3 sub-services to achieve redundancy.
    /// </summary>
    public class HAKsiService : IKsiService
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private readonly object _aggregatorConfigChangedLock = new object();
        private readonly object _extenderConfigChangedLock = new object();
        private readonly Dictionary<IKsiService, AggregatorConfig> _currentAggregatorConfigList = new Dictionary<IKsiService, AggregatorConfig>();
        private readonly Dictionary<IKsiService, ExtenderConfig> _currentExtenderConfigList = new Dictionary<IKsiService, ExtenderConfig>();
        private AggregatorConfig _currentAggregatorConfig;
        private ExtenderConfig _currentExtenderConfig;

        /// <summary>
        /// Aggregator configuration changed event.
        /// It is raised when a sub-service aggregation configuration changes and it changes consolidated configuration.
        /// </summary>
        public event EventHandler<AggregatorConfigChangedEventArgs> AggregatorConfigChanged;

        /// <summary>
        /// Extender configuration changed event.
        /// It is raised when a sub-service extender configuration changes and it changes consolidated configuration.
        /// </summary>
        public event EventHandler<ExtenderConfigChangedEventArgs> ExtenderConfigChanged;

        /// <summary>
        /// Create high availability KSI service
        /// </summary>
        /// <param name="signingServices">List of signing services. Max 3 allowed.</param>
        /// <param name="extendingServices">List of extending services. Max 3 allowed.</param>
        /// <param name="publicationsFileService">Publications file service</param>
        public HAKsiService(IList<IKsiService> signingServices,
                            IList<IKsiService> extendingServices,
                            IKsiService publicationsFileService)
        {
            if (signingServices != null)
            {
                if (signingServices.Count > 3)
                {
                    throw new HAKsiServiceException("Cannot use more than 3 signing services.");
                }

                SigningServices = new ReadOnlyCollection<IKsiService>(signingServices);

                foreach (IKsiService service in SigningServices)
                {
                    service.AggregatorConfigChanged += SigningService_AggregatorConfigChanged;
                }
            }
            else
            {
                SigningServices = new ReadOnlyCollection<IKsiService>(new List<IKsiService>());
            }

            if (extendingServices != null)
            {
                if (extendingServices.Count > 3)
                {
                    throw new HAKsiServiceException("Cannot use more than 3 extending services.");
                }

                ExtendingServices = new ReadOnlyCollection<IKsiService>(extendingServices);

                foreach (IKsiService service in ExtendingServices)
                {
                    service.ExtenderConfigChanged += ExtendingService_ExtenderConfigChanged;
                }
            }
            else
            {
                ExtendingServices = new ReadOnlyCollection<IKsiService>(new List<IKsiService>());
            }

            PublicationsFileService = publicationsFileService;
        }

        /// <summary>
        /// Collection of signing sub-services. 
        /// </summary>
        public ReadOnlyCollection<IKsiService> SigningServices { get; }

        /// <summary>
        /// Collection of extending sub-services.
        /// </summary>
        public ReadOnlyCollection<IKsiService> ExtendingServices { get; }

        /// <summary>
        /// Publications file service. 
        /// </summary>
        public IKsiService PublicationsFileService { get; }

        /// <summary>
        /// Create signature with given data hash (sync). 
        /// Sends the request to all the sub-services in parallel. First successful response is used. Request fails only if all the sub-services fail.
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature Sign(DataHash hash, uint level = 0)
        {
            return EndSign(BeginSign(hash, level, null, null));
        }

        /// <summary>
        /// Begin create signature with given data hash (async).
        /// Sends the request to all the sub-services in parallel. First successful response is used. Request fails only if all the sub-services fail.
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginSign(DataHash hash, AsyncCallback callback, object asyncState)
        {
            return BeginSign(hash, 0, callback, asyncState);
        }

        /// <summary>
        /// Begin create signature with given data hash (async).
        /// Sends the request to all the sub-services in parallel. First successful response is used. Request fails only if all the sub-services fail.
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginSign(DataHash hash, uint level, AsyncCallback callback, object asyncState)
        {
            Logger.Debug("Begin HA sign (hash: {0}; level: {1})", hash, level);
            return new HASignRequestRunner(SigningServices, hash, level).BeginRequest(callback, asyncState);
        }

        /// <summary>
        /// Get sign request response payload (async).
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>Request response payload</returns>
        public SignRequestResponsePayload GetSignResponsePayload(IAsyncResult asyncResult)
        {
            HAAsyncResult ar = GetHAAsyncResult(asyncResult);
            HASignRequestRunner requestRunner = ar.RequestRunner as HASignRequestRunner;
            if (requestRunner == null)
            {
                throw new HAKsiServiceException("Invalid request runner: " + ar.RequestRunner.GetType() + "; Expected type: " + typeof(HASignRequestRunner));
            }
            return requestRunner.GetSignResponsePayload(ar);
        }

        /// <summary>
        /// End create signature (async)
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature EndSign(IAsyncResult asyncResult)
        {
            HAAsyncResult ar = GetHAAsyncResult(asyncResult);
            HASignRequestRunner runner = GetRequestRunner<HASignRequestRunner>(ar);
            return runner.EndSign(ar);
        }

        /// <summary>
        /// Get additional aggregator configuration data (sync).
        /// Sends the request to all the sub-services in parallel. Successful responses are consolidated and the consolidated result is returned. Request fails only if all the sub-services fail.
        /// </summary>
        /// <returns>Aggregator configuration data</returns>
        public AggregatorConfig GetAggregatorConfig()
        {
            return EndGetAggregatorConfig(BeginGetAggregatorConfig(null, null));
        }

        /// <summary>
        /// Begin get additional aggregator configuration data (async)
        /// Sends the request to all the sub-services in parallel. Successful responses are consolidated and the consolidated result is returned. Request fails only if all the sub-services fail.
        /// </summary>
        /// <param name="callback">callback when aggregator configuration request is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginGetAggregatorConfig(AsyncCallback callback, object asyncState)
        {
            Logger.Debug("Begin HA aggregator config request.");
            return new HAAggregatorConfigRequestRunner(SigningServices).BeginRequest(callback, asyncState);
        }

        /// <summary>
        /// End get additional aggregator configuration data (async)
        /// </summary>
        /// <param name="asyncResult"></param>
        /// <returns>Aggregator configuration data</returns>
        public AggregatorConfig EndGetAggregatorConfig(IAsyncResult asyncResult)
        {
            HAAsyncResult haAsyncResult = GetHAAsyncResult(asyncResult);
            HAAggregatorConfigRequestRunner runner = GetRequestRunner<HAAggregatorConfigRequestRunner>(haAsyncResult);
            AggregatorConfig config = runner.EndGetAggregatorConfig(haAsyncResult);

            if (config == null)
            {
                lock (_aggregatorConfigChangedLock)
                {
                    _currentAggregatorConfigList.Clear();
                    _currentAggregatorConfig = null;
                }

                HAKsiServiceException ex = new HAKsiServiceException("Could not get aggregator configuration.", haAsyncResult.Errors);
                Logger.Warn(ex);
                AggregatorConfigChangedEventArgs aggregatorConfigChangedEventArgs = new AggregatorConfigChangedEventArgs(ex, this);
                AggregatorConfigChanged?.Invoke(this, aggregatorConfigChangedEventArgs);
                throw ex;
            }

            // if sub-service config request failed then remove corresponding config from cache
            foreach (HAKsiSubServiceException ex in haAsyncResult.Errors)
            {
                if (ex.ThrownBySubService == null)
                {
                    continue;
                }

                lock (_aggregatorConfigChangedLock)
                {
                    if (_currentAggregatorConfigList.ContainsKey(ex.ThrownBySubService))
                    {
                        _currentAggregatorConfigList.Remove(ex.ThrownBySubService);
                    }
                }
            }

            return config;
        }

        /// <summary>
        /// Extend to latest publication (sync).
        /// Sends the request to all the sub-services in parallel. First successful response is used. Request fails only if all the sub-services fail.
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <returns>extended calendar hash chain</returns>
        public CalendarHashChain Extend(ulong aggregationTime)
        {
            return EndExtend(BeginExtend(aggregationTime, null, null));
        }

        /// <summary>
        /// Extend to given publication (sync).
        /// Sends the request to all the sub-services in parallel. First successful response is used. Request fails only if all the sub-services fail.
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        /// <returns>extended calendar hash chain</returns>
        public CalendarHashChain Extend(ulong aggregationTime, ulong publicationTime)
        {
            return EndExtend(BeginExtend(aggregationTime, publicationTime, null, null));
        }

        /// <summary>
        /// Begin extend to latest publication (async).
        /// Sends the request to all the sub-services in parallel. First successful response is used. Request fails only if all the sub-services fail.
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginExtend(ulong aggregationTime, AsyncCallback callback, object asyncState)
        {
            Logger.Debug("Begin HA extend (aggregation time: {0})", aggregationTime);
            return new HAExtendRequestRunner(ExtendingServices, aggregationTime).BeginRequest(callback, asyncState);
        }

        /// <summary>
        /// Begin extend to given publication (async).
        /// Sends the request to all the sub-services in parallel. First successful response is used. Request fails only if all the sub-services fail.
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginExtend(ulong aggregationTime, ulong publicationTime, AsyncCallback callback, object asyncState)
        {
            Logger.Debug("Begin HA extend (aggregation time: {0}; publication time: {1})", aggregationTime, publicationTime);
            return new HAExtendRequestRunner(ExtendingServices, aggregationTime, publicationTime).BeginRequest(callback, asyncState);
        }

        /// <summary>
        /// End extend (async).
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>extended calendar hash chain</returns>
        public CalendarHashChain EndExtend(IAsyncResult asyncResult)
        {
            HAAsyncResult ar = GetHAAsyncResult(asyncResult);
            HAExtendRequestRunner runner = GetRequestRunner<HAExtendRequestRunner>(ar);
            return runner.EndExtend(ar);
        }

        /// <summary>
        /// Get additional extender configuration data (sync)
        /// Sends the request to all the sub-services in parallel. Successful responses are consolidated and the consolidated result is returned. Request fails only if all the sub-services fail.
        /// </summary>
        /// <returns>Extender configuration data</returns>
        public ExtenderConfig GetExtenderConfig()
        {
            return EndGetExtenderConfig(BeginGetExtenderConfig(null, null));
        }

        /// <summary>
        /// Begin get additional extender configuration data (async)
        /// Sends the request to all the sub-services in parallel. Successful responses are consolidated and the consolidated result is returned. Request fails only if all the sub-services fail.
        /// </summary>
        /// <param name="callback">callback when extnder configuration request is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginGetExtenderConfig(AsyncCallback callback, object asyncState)
        {
            Logger.Debug("Begin HA extender config request.");
            return new HAExtenderConfigRequestRunner(ExtendingServices).BeginRequest(callback, asyncState);
        }

        /// <summary>
        /// End get additional extender configuration data (async)
        /// </summary>
        /// <param name="asyncResult"></param>
        /// <returns>Extender configuration data</returns>
        public ExtenderConfig EndGetExtenderConfig(IAsyncResult asyncResult)
        {
            HAAsyncResult haAsyncResult = GetHAAsyncResult(asyncResult);
            HAExtenderConfigRequestRunner runner = GetRequestRunner<HAExtenderConfigRequestRunner>(haAsyncResult);
            ExtenderConfig config = runner.EndGetExtenderConfig(haAsyncResult);

            if (config == null)
            {
                lock (_extenderConfigChangedLock)
                {
                    _currentExtenderConfigList.Clear();
                    _currentExtenderConfig = null;
                }

                HAKsiServiceException ex = new HAKsiServiceException("Could not get extender configuration.", haAsyncResult.Errors);
                Logger.Warn(ex);
                ExtenderConfigChangedEventArgs extenderConfigChangedEventArgs = new ExtenderConfigChangedEventArgs(ex, this);
                ExtenderConfigChanged?.Invoke(this, extenderConfigChangedEventArgs);
                throw ex;
            }

            // if sub-service config request failed then remove corresponding config from cache
            foreach (HAKsiSubServiceException ex in haAsyncResult.Errors)
            {
                if (ex.ThrownBySubService == null)
                {
                    continue;
                }

                lock (_extenderConfigChangedLock)
                {
                    if (_currentExtenderConfigList.ContainsKey(ex.ThrownBySubService))
                    {
                        _currentExtenderConfigList.Remove(ex.ThrownBySubService);
                    }
                }
            }

            return config;
        }

        /// <summary>
        /// Get publications file (sync).
        /// Sends the request to all the sub-services in parallel. First successful response is used. Request fails only if all the sub-services fail.
        /// </summary>
        /// <returns>Publications file</returns>
        public IPublicationsFile GetPublicationsFile()
        {
            return EndGetPublicationsFile(BeginGetPublicationsFile(null, null));
        }

        /// <summary>
        /// Begin get publications file (async).
        /// Sends the request to all the sub-services in parallel. First successful response is used. Request fails only if all the sub-services fail.
        /// </summary>
        /// <param name="callback">callback when publications file is downloaded</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState)
        {
            if (PublicationsFileService == null)
            {
                throw new HAKsiServiceException("Publications file service is missing.");
            }

            return PublicationsFileService.BeginGetPublicationsFile(callback, asyncState);
        }

        /// <summary>
        /// End get publications file (async).
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>publications file</returns>
        public IPublicationsFile EndGetPublicationsFile(IAsyncResult asyncResult)
        {
            if (PublicationsFileService == null)
            {
                throw new HAKsiServiceException("Publications file service is missing.");
            }

            return PublicationsFileService.EndGetPublicationsFile(asyncResult);
        }

        /// <summary>
        /// List of aggregator sub-service addresses
        /// </summary>
        public string AggregatorAddress
        {
            get
            {
                StringBuilder sb = new StringBuilder();
                foreach (IKsiService service in SigningServices)
                {
                    sb.Append(service.AggregatorAddress + "; ");
                }
                return sb.ToString();
            }
        }

        /// <summary>
        /// List of extender sub-service addresses
        /// </summary>
        public string ExtenderAddress
        {
            get
            {
                StringBuilder sb = new StringBuilder();
                foreach (IKsiService service in ExtendingServices)
                {
                    sb.Append(service.ExtenderAddress + "; ");
                }
                return sb.ToString();
            }
        }

        /// <summary>
        /// Publications file url
        /// </summary>
        public string PublicationsFileAddress => PublicationsFileService?.PublicationsFileAddress;

        private static HAAsyncResult GetHAAsyncResult(IAsyncResult asyncResult)
        {
            if (asyncResult == null)
            {
                throw new ArgumentNullException(nameof(asyncResult));
            }

            HAAsyncResult ar = asyncResult as HAAsyncResult;

            if (ar == null)
            {
                throw new HAKsiServiceException("Invalid " + nameof(asyncResult) + ", could not cast to correct object.");
            }

            return ar;
        }

        private static T GetRequestRunner<T>(HAAsyncResult haAsyncResult) where T : class
        {
            T runner = haAsyncResult.RequestRunner as T;

            if (runner == null)
            {
                throw new HAKsiServiceException(string.Format("Invalid async result. Containing invalid request runner of type {0}; Expected type: {1}",
                    haAsyncResult.RequestRunner.GetType(), typeof(T)));
            }
            return runner;
        }

        private void SigningService_AggregatorConfigChanged(object sender, AggregatorConfigChangedEventArgs e)
        {
            if (AggregatorConfigChanged == null)
            {
                return;
            }

            lock (_aggregatorConfigChangedLock)
            {
                try
                {
                    Logger.Debug("Sub-service AggregationConfig changed: " + e.AggregatorConfig + "; Sub-service: " + e.KsiService.AggregatorAddress);

                    if (e.AggregatorConfig == null)
                    {
                        throw new ArgumentNullException(nameof(e.AggregatorConfig));
                    }

                    _currentAggregatorConfigList[e.KsiService] = e.AggregatorConfig;
                    RecalculateAggregatorConfig();
                }
                catch (Exception ex)
                {
                    Logger.Warn("HA aggregator configuration change handling failed", ex);
                    throw;
                }
            }
        }

        private void RecalculateAggregatorConfig()
        {
            AggregatorConfig mergedConfig = null;

            foreach (IKsiService service in SigningServices)
            {
                if (!_currentAggregatorConfigList.ContainsKey(service))
                {
                    continue;
                }

                AggregatorConfig config = _currentAggregatorConfigList[service];
                Logger.Debug("AggregatorConfig in cache: " + config + "; Sub-service: " + service.AggregatorAddress);
                mergedConfig = HAAggregatorConfigRequestRunner.MergeConfigs(mergedConfig, config);
            }

            if (_currentAggregatorConfig == null || !_currentAggregatorConfig.Equals(mergedConfig))
            {
                Logger.Debug("New merged AggregatorConfig: " + mergedConfig);
                _currentAggregatorConfig = mergedConfig;
                AggregatorConfigChanged?.Invoke(this, new AggregatorConfigChangedEventArgs(mergedConfig, this));
            }
            else
            {
                Logger.Debug("Merged AggregationConfig not changed.");
            }
        }

        private void ExtendingService_ExtenderConfigChanged(object sender, ExtenderConfigChangedEventArgs e)
        {
            if (ExtenderConfigChanged == null)
            {
                return;
            }

            lock (_extenderConfigChangedLock)
            {
                try
                {
                    Logger.Debug("Sub-service ExtenderConfig changed: " + e.ExtenderConfig + "; Sub-service: " + e.KsiService.ExtenderAddress);

                    if (e.ExtenderConfig == null)
                    {
                        throw new ArgumentNullException(nameof(e.ExtenderConfig));
                    }

                    _currentExtenderConfigList[e.KsiService] = e.ExtenderConfig;

                    RecalculateExtenderConfig();
                }
                catch (Exception ex)
                {
                    Logger.Warn("HA extender configuration change handling failed", ex);
                    throw;
                }
            }
        }

        private void RecalculateExtenderConfig()
        {
            ExtenderConfig mergedConfig = null;

            foreach (IKsiService service in ExtendingServices)
            {
                if (!_currentExtenderConfigList.ContainsKey(service))
                {
                    continue;
                }

                ExtenderConfig config = _currentExtenderConfigList[service];
                Logger.Debug("ExtenderConfig in cache: " + config + "; Sub-service: " + service.ExtenderAddress);
                mergedConfig = HAExtenderConfigRequestRunner.MergeConfigs(mergedConfig, config);
            }

            if (_currentExtenderConfig == null || !_currentExtenderConfig.Equals(mergedConfig))
            {
                Logger.Debug("New merged ExtenderConfig: " + mergedConfig);
                _currentExtenderConfig = mergedConfig;
                ExtenderConfigChanged?.Invoke(this, new ExtenderConfigChangedEventArgs(mergedConfig, this));
            }
            else
            {
                Logger.Debug("Merged ExtenderConfig not changed.");
            }
        }
    }
}