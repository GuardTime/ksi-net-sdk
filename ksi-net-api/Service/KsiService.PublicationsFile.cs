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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     KSI service.
    /// </summary>
    public partial class KsiService
    {
        /// <summary>
        ///     Get publications file (sync).
        /// </summary>
        /// <returns>Publications file</returns>
        public IPublicationsFile GetPublicationsFile()
        {
            return EndGetPublicationsFile(BeginGetPublicationsFile(null, null));
        }

        /// <summary>
        ///     Begin get publications file (async).
        /// </summary>
        /// <param name="callback">callback when publications file is downloaded</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState)
        {
            if (_publicationsFileServiceProtocol == null)
            {
                throw new KsiServiceException("Publications file service protocol is missing from service.");
            }

            IAsyncResult serviceProtocolAsyncResult = _publicationsFileServiceProtocol.BeginGetPublicationsFile(callback, asyncState);
            return new PublicationsFileKsiServiceAsyncResult(serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        ///     End get publications file (async).
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>publications file</returns>
        public IPublicationsFile EndGetPublicationsFile(IAsyncResult asyncResult)
        {
            if (_publicationsFileServiceProtocol == null)
            {
                throw new KsiServiceException("Publications file service protocol is missing from service.");
            }

            if (asyncResult == null)
            {
                throw new KsiServiceException("Invalid IAsyncResult: null.");
            }

            KsiServiceAsyncResult serviceAsyncResult = asyncResult as PublicationsFileKsiServiceAsyncResult;
            if (serviceAsyncResult == null)
            {
                throw new KsiServiceException("Invalid IAsyncResult, could not cast to correct object.");
            }

            if (!serviceAsyncResult.IsCompleted)
            {
                serviceAsyncResult.AsyncWaitHandle.WaitOne();
            }

            byte[] data = _publicationsFileServiceProtocol.EndGetPublicationsFile(serviceAsyncResult.ServiceProtocolAsyncResult);
            return _publicationsFileFactory.Create(data);
        }

        /// <summary>
        ///     Publications file KSI service async result.
        /// </summary>
        private class PublicationsFileKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            public PublicationsFileKsiServiceAsyncResult(IAsyncResult serviceProtocolAsyncResult, object asyncState)
                : base(serviceProtocolAsyncResult, asyncState)
            {
            }
        }
    }
}