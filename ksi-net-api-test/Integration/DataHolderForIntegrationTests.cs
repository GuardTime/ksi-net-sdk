using System;
using System.Collections.Generic;
using NUnit.Framework;
using NUnit.Framework.Constraints;

namespace Guardtime.KSI.Integration
{
    public class DataHolderForIntegrationTests
    {
        private string _testFile;
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
            this._testFile = inputData[0];

            this._sigantureReadInFails = inputData[1].ToLower().Equals("true");

            if (inputData[2] == null)
            {
                throw new ArgumentNullException(string.Format("Failure code is null"));
            }

            string[] expectedValues = { "ok", "fail", "na" };
            if (Array.IndexOf(expectedValues, inputData[2].ToLower()) > -1)
            { 
                this._expectedVerificationResultCode = inputData[2];
            }
            else
            {
                throw new ArgumentException(string.Format("Invalid argument value for expected verification result." + inputData[2]));
            }

            if (inputData[3] == null)
            {
                throw new ArgumentNullException(string.Format("Expected exception is null"));
            }
            this._expectedExceptionClass = inputData[3];

            if (inputData[4] == null)
            {
                throw new ArgumentNullException(string.Format("Expected exception message is null"));
            }
            this._exceptionMessage = inputData[4];

            if (inputData[5] == null)
            {
                throw new ArgumentNullException(string.Format("Expected failed rule is null"));
            }
            this._expectedRule = inputData[5];
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

        public void SetTestFile(string testFile)
        {
            this._testFile = testFile;
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