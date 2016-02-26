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
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Guardtime.KSI.Integration
{
    public class CommonGetTestFilesAndResults
    {
        public static IEnumerable<DataHolderForIntegrationTests> GetKeyBasedVerificationData()
        {
            return GetTestFilesAndResults("resources/Integration/KeyBasedVerificationData.txt").Cast<object>().Cast<DataHolderForIntegrationTests>();
        }

        public static IEnumerable<DataHolderForIntegrationTests> GetKeyBasedVerificationDataWithNoPublication()
        {
            return GetTestFilesAndResults("resources/Integration/KeyBasedVerificationDataWithNoPublication.txt").Cast<object>().Cast<DataHolderForIntegrationTests>();
        }

        public static IEnumerable<DataHolderForIntegrationTests> GetPublicationFileBasedVerificationData()
        {
            return GetTestFilesAndResults("resources/Integration/PublicationFileBasedVerificationData.txt").Cast<object>().Cast<DataHolderForIntegrationTests>();
        }

        public static IEnumerable<DataHolderForIntegrationTests> GetPublicationFileBasedVerificationNoExtendingData()
        {
            return GetTestFilesAndResults("resources/Integration/PublicationFileBasedVerificationDataNoExtending.txt").Cast<object>().Cast<DataHolderForIntegrationTests>();
        }

        public static IEnumerable<DataHolderForIntegrationTests> GetPublicationStringVerificationData()
        {
            return GetTestFilesAndResults("resources/Integration/PublicationStringVerificationData.txt").Cast<object>().Cast<DataHolderForIntegrationTests>();
        }

        public static IEnumerable<DataHolderForIntegrationTests> GetPublicationStringVerificationNoExtendingData()
        {
            return GetTestFilesAndResults("resources/Integration/PublicationStringVerificationNoExtendingData.txt").Cast<object>().Cast<DataHolderForIntegrationTests>();
        }

        public static IEnumerable<DataHolderForIntegrationTests> GetCalendarBasedVerificationData()
        {
            return GetTestFilesAndResults("resources/Integration/CalendarBasedVerificationData.txt").Cast<object>().Cast<DataHolderForIntegrationTests>();
        }

        private static IEnumerable GetTestFilesAndResults(string inFile)
        {
            using (StreamReader fileReader = new StreamReader(inFile))
            {
                string line;
                while ((line = fileReader.ReadLine()) != null)
                {
                    Console.WriteLine(line);
                    if (!line.StartsWith("#"))
                    {
                        yield return new DataHolderForIntegrationTests(line.Split(':'));
                    }
                }
            }
        }
    }
}
