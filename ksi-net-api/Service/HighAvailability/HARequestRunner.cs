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
using System.Text;
using Guardtime.KSI.Exceptions;
using NLog;

namespace Guardtime.KSI.Service.HighAvailability
{
    /// <summary>
    /// Class that is resposible for running high availablity sub-service requests and giving a result based on the requests.
    /// </summary>
    public abstract class HARequestRunner
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private readonly IList<IKsiService> _subServices;
        private readonly bool _returnAllResponses;

        /// <summary>
        /// Create high availablity request runner instance.
        /// </summary>
        /// <param name="subServices">List of sub-services</param>
        /// <param name="returnAllResponses">If true then all sub-service requests are returned as result. If false then the first sub-service response is returned as result.</param>
        protected HARequestRunner(IList<IKsiService> subServices, bool returnAllResponses = false)
        {
            _subServices = subServices;
            _returnAllResponses = returnAllResponses;
        }

        /// <summary>
        /// Begin HA request.
        /// </summary>
        /// <param name="callback">callback when HA request is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns></returns>
        public HAAsyncResult BeginRequest(AsyncCallback callback, object asyncState)
        {
            if (_subServices.Count == 0)
            {
                throw new HAKsiServiceException("Sub-services are missing.");
            }

            HAAsyncResult haAsyncResult = new HAAsyncResult(callback, asyncState, this);

            for (int index = 0; index < _subServices.Count; index++)
            {
                Action<SubServiceRunArgs> action = RunSubService;
                action.BeginInvoke(new SubServiceRunArgs(haAsyncResult, index), null, null);
            }

            CheckComplete(haAsyncResult);

            return haAsyncResult;
        }

        private void RunSubService(SubServiceRunArgs subServiceRunArgs)
        {
            IKsiService service = GetService(subServiceRunArgs);

            try
            {
                IAsyncResult asyncResult = SubServiceBeginRequest(service);
                asyncResult.AsyncWaitHandle.WaitOne();
                subServiceRunArgs.HAAsyncResult.ResultTlvs.Add(SubServiceEndRequest(service, asyncResult));

                if (subServiceRunArgs.HAAsyncResult.IsCompleted)
                {
                    return;
                }

                if (!_returnAllResponses)
                {
                    subServiceRunArgs.HAAsyncResult.SetComplete();
                    return;
                }
            }
            catch (Exception ex)
            {
                HandleException(ex, service, subServiceRunArgs.HAAsyncResult);
            }

            CheckComplete(subServiceRunArgs.HAAsyncResult);
        }

        private IKsiService GetService(SubServiceRunArgs subServiceRunArgs)
        {
            return _subServices != null && _subServices.Count > subServiceRunArgs.ServiceIndex ? _subServices[subServiceRunArgs.ServiceIndex] : null;
        }

        /// <summary>
        /// Begin sub-service request.
        /// </summary>
        /// <param name="service">sub-service</param>
        /// <returns></returns>
        protected abstract IAsyncResult SubServiceBeginRequest(IKsiService service);

        /// <summary>
        /// End sub-service request.
        /// </summary>
        /// <param name="service">sub-service</param>
        /// <param name="asyncResult">async result</param>
        /// <returns></returns>
        protected abstract object SubServiceEndRequest(IKsiService service, IAsyncResult asyncResult);

        private void HandleException(Exception ex, IKsiService service, HAAsyncResult haAsyncResult)
        {
            string message = "Using sub-service failed.";

            if (service != null)
            {
                message += " " + SubServiceToString(service);
            }

            if (ex != null)
            {
                message += Environment.NewLine + ex;
            }

            Logger.Warn(message, ex);
            haAsyncResult.Errors.Add(new HAKsiSubServiceException(service, message, ex));
        }

        /// <summary>
        /// Returns a string that represents the given sub-service.
        /// </summary>
        /// <param name="service">sub-service</param>
        /// <returns></returns>
        protected abstract string SubServiceToString(IKsiService service);

        /// <summary>
        /// Ends HA request and returns responses of all successful sub-service requests.
        /// </summary>
        /// <param name="haAsyncResult">HA async result</param>
        /// <returns></returns>
        public object[] EndRequestMulti(HAAsyncResult haAsyncResult)
        {
            if (!haAsyncResult.IsCompleted)
            {
                haAsyncResult.AsyncWaitHandle.WaitOne();
            }

            return haAsyncResult.ResultTlvs.ToArray();
        }

        /// <summary>
        /// Ends HA request and returns the first successful sub-service response.
        /// </summary>
        /// <typeparam name="T">Type of response to be returned</typeparam>
        /// <param name="haAsyncResult">HA async result</param>
        /// <returns></returns>
        protected T EndRequest<T>(HAAsyncResult haAsyncResult) where T : class
        {
            object[] results = EndRequestMulti(haAsyncResult);

            if (results.Length == 0)
            {
                throw new HAKsiServiceException("All sub-requests failed.", haAsyncResult.Errors);
            }

            foreach (object obj in results)
            {
                T result = obj as T;
                if (result != null)
                {
                    return result;
                }
            }

            throw new HAKsiServiceException("Could not get request response of type " + typeof(T) + Environment.NewLine + "Available responses: " + Environment.NewLine +
                                            ResultTlvsToString(results));
        }

        private string ResultTlvsToString(object[] tlvs)
        {
            StringBuilder sb = new StringBuilder();
            foreach (object tlv in tlvs)
            {
                sb.AppendLine("TLV: " + tlv);
            }
            return sb.ToString();
        }

        private void CheckComplete(HAAsyncResult haAsyncResult)
        {
            if (_returnAllResponses)
            {
                if (haAsyncResult.ResultTlvs.Count + haAsyncResult.Errors.Count == _subServices.Count)
                {
                    haAsyncResult.SetComplete();
                }
            }
            else
            {
                if (haAsyncResult.Errors.Count >= _subServices.Count)
                {
                    haAsyncResult.SetComplete();
                }
            }
        }

        private class SubServiceRunArgs
        {
            public HAAsyncResult HAAsyncResult { get; }
            public int ServiceIndex { get; }

            public SubServiceRunArgs(HAAsyncResult haAsyncResult, int serviceIndex)
            {
                if (haAsyncResult == null)
                {
                    throw new ArgumentNullException(nameof(haAsyncResult));
                }
                HAAsyncResult = haAsyncResult;
                ServiceIndex = serviceIndex;
            }
        }
    }
}