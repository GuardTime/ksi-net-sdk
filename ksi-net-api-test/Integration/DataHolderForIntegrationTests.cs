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
using System.Collections.Generic;

namespace Guardtime.KSI.Integration
{
    public class DataHolderForIntegrationTests
    {
        private readonly string _testFile;
        private readonly bool _sigantureReadInFails;
        private readonly string _expectedVerificationResultCode;
        private readonly string _expectedExceptionClass;
        private readonly string _exceptionMessage;
        private readonly string _expectedRule;

        public DataHolderForIntegrationTests(IReadOnlyList<string> inputData)
        {
            if (inputData[0] == null)
            {
                throw new ArgumentNullException(string.Format("Test file is null"));
            }
            _testFile = inputData[0];

            _sigantureReadInFails = inputData[1].ToLower().Equals("true");

            if (inputData[2] == null)
            {
                throw new ArgumentNullException(string.Format("Failure code is null"));
            }

            string[] expectedValues = { "ok", "fail", "na" };
            if (Array.IndexOf(expectedValues, inputData[2].ToLower()) > -1)
            { 
                _expectedVerificationResultCode = inputData[2];
            }
            else
            {
                throw new ArgumentException(string.Format("Invalid argument value for expected verification result." + inputData[2]));
            }

            if (inputData[3] == null)
            {
                throw new ArgumentNullException(string.Format("Expected exception is null"));
            }
            _expectedExceptionClass = inputData[3];

            if (inputData[4] == null)
            {
                throw new ArgumentNullException(string.Format("Expected exception message is null"));
            }
            _exceptionMessage = inputData[4];

            if (inputData[5] == null)
            {
                throw new ArgumentNullException(string.Format("Expected failed rule is null"));
            }
            _expectedRule = inputData[5];
        }

        public string GetTestFile()
        {
            return _testFile;
        }

        public bool GetSigantureReadInFails()
        {
            return _sigantureReadInFails;
        }

        public string GetExpectedVerificationResultCode()
        {
            return _expectedVerificationResultCode;
        }

        public string GetExpectedExceptionClass()
        {
            return _expectedExceptionClass;
        }

        public string GetExpectedExceptionMessage()
        {
            return _exceptionMessage;
        }

        public string GetExpectedRule()
        {
            return _expectedRule;
        }

        public string GetTestDataInformation()
        {
            return "Signature File: " + _testFile + "; Fail at siganture loading: " + _sigantureReadInFails + 
                "; Expected verification result code: " + _expectedVerificationResultCode +
                "; Expected Exception: " + _expectedExceptionClass + "; Expected Exception Message: " + _exceptionMessage +
                "; Expected rule that fails: " + _expectedRule;
        }
    }
}