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
