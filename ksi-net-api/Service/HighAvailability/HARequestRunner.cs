/*
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
using System.Collections.Generic;
using System.Text;
using System.Threading;
using Guardtime.KSI.Exceptions;
using NLog;

namespace Guardtime.KSI.Service.HighAvailability
{
    /// <summary>
    /// Class that is resposible for running high availablity sub-service requests and giving a result based on the requests.
    /// In case signing request we need to wait HA service end request call (EndSign or GetSignResponsePayload) before sub-services end request calls can be made.
    /// </summary>
    public abstract class HARequestRunner
    {
        private delegate void RunSubServiceDelegate(HAAsyncResult haAsyncResult, int serviceIndex);

        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private readonly int _requestTimeout;
        private readonly IList<IKsiService> _subServices;
        private readonly bool _returnAllResponses;
        private readonly RunSubServiceDelegate _runSubServiceDelegate;
        private ManualResetEvent _endCallWaitHandle;
        private ManualResetEvent _subServiceFirstResultsWaitHandle;
        private readonly object _resultTlvLock;
        private readonly List<object> _resultTlvs;

        /// <summary>
        /// Create high availablity request runner instance.
        /// </summary>
        /// <param name="subServices">List of sub-services</param>
        /// <param name="requestTimeout">request timeout in milliseconds</param>
        /// <param name="returnAllResponses">If true then all sub-service requests are returned as result. If false then the first sub-service response is returned as result.</param>
        protected HARequestRunner(IList<IKsiService> subServices, uint requestTimeout, bool returnAllResponses = false)
        {
            _subServices = subServices;
            _requestTimeout = (int)requestTimeout;
            _returnAllResponses = returnAllResponses;
            _runSubServiceDelegate = RunSubService;
            _resultTlvLock = new object();
            _resultTlvs = new List<object>();
            SubServiceErrors = new List<HAKsiSubServiceException>();
        }

        /// <summary>
        /// List of errors thrown by sub-services.
        /// </summary>
        public List<HAKsiSubServiceException> SubServiceErrors { get; }

        /// <summary>
        /// Begin HA request.
        /// </summary>
        /// <param name="callback">callback when HA request is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <param name="waitEndCall">If true then HA end request call (eg. EndSign) is waited before sub-service end request call can be made.</param>
        /// <returns></returns>
        public virtual HAAsyncResult BeginRequest(AsyncCallback callback, object asyncState, bool waitEndCall = false)
        {
            if (_subServices.Count == 0)
            {
                throw new HAKsiServiceException("Sub-services are missing.");
            }

            HAAsyncResult haAsyncResult = new HAAsyncResult(callback, asyncState, this);

            if (waitEndCall)
            {
                _endCallWaitHandle = new ManualResetEvent(false);
                _subServiceFirstResultsWaitHandle = new ManualResetEvent(false);
            }

            for (int index = 0; index < _subServices.Count; index++)
            {
                _runSubServiceDelegate.BeginInvoke(haAsyncResult, index, EndRunSubService, null);
            }

            CheckComplete(haAsyncResult);

            return haAsyncResult;
        }

        private void EndRunSubService(IAsyncResult asyncResult)
        {
            try
            {
                _runSubServiceDelegate.EndInvoke(asyncResult);
            }
            catch (Exception ex)
            {
                Logger.Warn("Ending running sub service failed.", ex);
            }
        }

        private void RunSubService(HAAsyncResult haAsyncResult, int serviceIndex)
        {
            IKsiService service = GetService(serviceIndex);

            try
            {
                IAsyncResult asyncResult = SubServiceBeginRequest(service);
                if (!asyncResult.AsyncWaitHandle.WaitOne(_requestTimeout))
                {
                    throw new HAKsiServiceException("Sub-service request timed out.");
                }

                if (_endCallWaitHandle != null)
                {
                    // We need to wait HA service end call (eg. EndSign)
                    // Mark HA async request as complete
                    haAsyncResult.SetComplete();

                    // Wait for HA service end call.
                    if (!_endCallWaitHandle.WaitOne(_requestTimeout))
                    {
                        throw new HAKsiServiceException("Wait end call timed out.");
                    }
                }

                object subServiceEndRequest = SubServiceEndRequest(service, asyncResult);

                lock (_resultTlvLock)
                {
                    _resultTlvs.Add(subServiceEndRequest);
                }

                _subServiceFirstResultsWaitHandle?.Set();

                if (haAsyncResult.IsCompleted)
                {
                    return;
                }

                if (!_returnAllResponses)
                {
                    haAsyncResult.SetComplete();
                    return;
                }
            }
            catch (Exception ex)
            {
                HandleException(ex, service);
            }

            CheckComplete(haAsyncResult);
        }

        private IKsiService GetService(int serviceIndex)
        {
            return _subServices != null && _subServices.Count > serviceIndex ? _subServices[serviceIndex] : null;
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

        private void HandleException(Exception ex, IKsiService service)
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
            SubServiceErrors.Add(new HAKsiSubServiceException(service, message, ex));
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
                if (!haAsyncResult.AsyncWaitHandle.WaitOne(_requestTimeout))
                {
                    throw new HAKsiServiceException("HA service request timed out.");
                }
            }

            lock (_resultTlvLock)
            {
                return _resultTlvs.ToArray();
            }
        }

        /// <summary>
        /// Ends HA request and returns the first successful sub-service response.
        /// </summary>
        /// <typeparam name="T">Type of response to be returned</typeparam>
        /// <param name="haAsyncResult">HA async result</param>
        /// <returns></returns>
        protected T EndRequest<T>(HAAsyncResult haAsyncResult) where T : class
        {
            if (_subServiceFirstResultsWaitHandle != null)
            {
                // notify that end request is called
                _endCallWaitHandle?.Set();
                // wait for first successful sub-service result
                if (!_subServiceFirstResultsWaitHandle.WaitOne(_requestTimeout))
                {
                    throw new HAKsiServiceException("HA service request timed out.");
                }
            }

            object[] results = EndRequestMulti(haAsyncResult);

            if (results.Length == 0)
            {
                throw new HAKsiServiceException("All sub-requests failed.", SubServiceErrors);
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

        private int ResultTlvCount
        {
            get
            {
                lock (_resultTlvLock)
                {
                    return _resultTlvs.Count;
                }
            }
        }

        private void CheckComplete(HAAsyncResult haAsyncResult)
        {
            if (_returnAllResponses)
            {
                if (ResultTlvCount + SubServiceErrors.Count == _subServices.Count)
                {
                    haAsyncResult.SetComplete();
                    _subServiceFirstResultsWaitHandle?.Set();
                }
            }
            else
            {
                if (SubServiceErrors.Count >= _subServices.Count)
                {
                    haAsyncResult.SetComplete();
                    _subServiceFirstResultsWaitHandle?.Set();
                }
            }
        }
    }
}