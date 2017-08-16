﻿/*
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
using System.IO;
using System.Threading;
using Guardtime.KSI.Service;
using Guardtime.KSI.Test.Properties;

namespace Guardtime.KSI.Test.Service
{
    public class TestKsiServiceProtocol : IKsiSigningServiceProtocol, IKsiExtendingServiceProtocol, IKsiPublicationsFileServiceProtocol
    {
        /// <summary>
        /// Return value of signing/extending request
        /// </summary>
        public byte[] RequestResult { get; set; }

        public IAsyncResult BeginSign(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            AsyncResult ar = new AsyncResult(data, asyncState);
            callback?.Invoke(ar);
            return ar;
        }

        public byte[] EndSign(IAsyncResult asyncResult)
        {
            return RequestResult;
        }

        public string AggregatorLocation => "test.aggregator.location";

        public IAsyncResult BeginExtend(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            return new AsyncResult(data, asyncState);
        }

        public byte[] EndExtend(IAsyncResult asyncResult)
        {
            return RequestResult;
        }

        public string ExtenderLocation => "test.extender.location";

        public IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState)
        {
            return new AsyncResult(null, asyncState);
        }

        public bool UseRequestResultAsPublicationsFileResponse { get; set; }

        public byte[] EndGetPublicationsFile(IAsyncResult asyncResult)
        {
            return UseRequestResultAsPublicationsFileResponse ? RequestResult : ReadFile(Resources.KsiPublicationsFile);
        }

        public string PublicationsFileLocation => "test.publications.file.location";

        private static byte[] ReadFile(string file)
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, file), FileMode.Open, FileAccess.Read))
            {
                byte[] data = new byte[stream.Length];
                stream.Read(data, 0, (int)stream.Length);

                return data;
            }
        }

        private class AsyncResult : IAsyncResult, IDisposable
        {
            private readonly ManualResetEvent _resetEvent = new ManualResetEvent(true);

            public AsyncResult(byte[] request, object asyncState)
            {
                AsyncState = asyncState;
            }

            public bool IsCompleted => true;

            public WaitHandle AsyncWaitHandle => _resetEvent;

            public object AsyncState { get; }

            public bool CompletedSynchronously => false;

            public void Dispose()
            {
                _resetEvent.Dispose();
            }
        }
    }
}