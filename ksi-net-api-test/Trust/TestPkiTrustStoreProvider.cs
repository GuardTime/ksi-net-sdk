﻿/*
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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Trust;

namespace Guardtime.KSI.Test.Trust
{
    public class TestPkiTrustStoreProvider : IPkiTrustProvider
    {
        private bool _verificationSuccessful = true;

        public TestPkiTrustStoreProvider(bool verificationSuccessful = true)
        {
            _verificationSuccessful = verificationSuccessful;
        }

        public void Verify(byte[] signedBytes, byte[] signatureBytes)
        {
            if (!_verificationSuccessful)
            {
                throw new PkiVerificationErrorException("Verification failed!");
            }
        }
    }
}