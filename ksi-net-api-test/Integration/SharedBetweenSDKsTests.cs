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
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Test.Service;
using Guardtime.KSI.Test.Signature.Verification;
using Guardtime.KSI.Trust;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Integration
{
    /// <summary>
    /// Tests that are shared between C, Java and .NET SDKs.
    /// </summary>
    [TestFixture]
    public class SharedBetweenSdksTests
    {
        private static IPublicationsFile _pubsFile;
        private const string ValidSignatureDir = "resources/signature/shared/valid-signatures/";
        private const string InvalidSignatureDir = "resources/signature/shared/invalid-signatures/";
        private const string PolicyVerificationDir = "resources/signature/shared/policy-verification-signatures/";
        private const string InternalPolicyVerificationDir = "resources/signature/shared/internal-policy-signatures/";

        [Test, TestCaseSource(nameof(GetInvalidSignatureTestData))]
        public void TestInvalidSignatures(TestingRow row)
        {
            RunTests(row, InvalidSignatureDir);
        }

        [Test, TestCaseSource(nameof(GetValidSignatureTestData))]
        public void TestValidSignatures(TestingRow row)
        {
            RunTests(row, ValidSignatureDir);
        }

        [Test, TestCaseSource(nameof(GetInternalPolicyVerificationSignatureTestData))]
        public void TestInternalPolicies(TestingRow row)
        {
            RunTests(row, InternalPolicyVerificationDir);
        }

        [Test, TestCaseSource(nameof(GetPolicyVerificationSignatureTestData))]
        public void TestPolicies(TestingRow row)
        {
            RunTests(row, PolicyVerificationDir);
        }

        private static void RunTests(TestingRow testingRow, string testDataDir)
        {
            Console.WriteLine(testingRow);

            IKsiSignature signature;

            try
            {
                signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, testDataDir + testingRow.FileName)));
            }
            catch (KsiException)
            {
                if (testingRow.ActionName != "parsing")
                {
                    throw;
                }
                return;
            }

            IVerificationContext verificationContext = GetVerificationContext(testingRow, signature, testDataDir, testingRow.ActionName == "userPublication");

            switch (testingRow.ActionName)
            {
                case "userPublication":
                    Verify(testingRow, new PublicationBasedVerificationPolicy(), verificationContext);
                    break;
                case "publicationsFile":
                    Verify(testingRow, new PublicationBasedVerificationPolicy(), verificationContext);
                    break;
                case "key":
                    Verify(testingRow,
                        new KeyBasedVerificationPolicy(),
                        verificationContext);
                    break;
                case "internal":
                    Verify(testingRow, new InternalVerificationPolicy(), verificationContext);
                    break;
                case "calendar":
                    Verify(testingRow, new CalendarBasedVerificationPolicy(), verificationContext);
                    break;
                case "parsing":
                    Assert.Fail("Parsing exception expected but nothing thrown.");
                    break;
                case "not-implemented":
                    break;
                default:
                    throw new Exception("Unknown testing action: " + testingRow.ActionName);
            }
        }

        private static IVerificationContext GetVerificationContext(TestingRow testingRow, IKsiSignature signature, string testDataDir, bool setUserPublication = false)
        {
            IPublicationsFile publicationsFile = null;
            IKsiService service;

            if (!setUserPublication)
            {
                publicationsFile = GetPublicationsFile(string.IsNullOrEmpty(testingRow.PublicationsFilePath) ? null : testDataDir + testingRow.PublicationsFilePath,
                    string.IsNullOrEmpty(testingRow.CertFilePath) ? null : testDataDir + testingRow.CertFilePath);
            }

            if (string.IsNullOrEmpty(testingRow.ResourceFile))
            {
                service = IntegrationTests.GetHttpKsiService();
            }
            else
            {
                TestKsiServiceProtocol protocol = new TestKsiServiceProtocol
                {
                    RequestResult = File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, testDataDir + testingRow.ResourceFile))
                };
                service =
                    new TestKsiService(
                        protocol,
                        new ServiceCredentials(Properties.Settings.Default.HttpSigningServiceUser, Properties.Settings.Default.HttpSigningServicePass,
                            TestUtil.GetHashAlgorithm(Properties.Settings.Default.HttpSigningServiceHmacAlgorithm)),
                        protocol,
                        new ServiceCredentials(Properties.Settings.Default.HttpExtendingServiceUser, Properties.Settings.Default.HttpExtendingServicePass,
                            TestUtil.GetHashAlgorithm(Properties.Settings.Default.HttpExtendingServiceHmacAlgorithm)),
                        protocol,
                        new PublicationsFileFactory(
                            new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))), 1, PduVersion.v2);
            }

            return new VerificationContext(signature)
            {
                DocumentHash = testingRow.InputHash,
                UserPublication = setUserPublication ? testingRow.PublicationData : null,
                IsExtendingAllowed = testingRow.IsExtendingAllowed,
                KsiService = service,
                PublicationsFile = publicationsFile,
                DocumentHashLevel = testingRow.InputHashLevel
            };
        }

        private static void Verify(TestingRow data, VerificationPolicy policy, IVerificationContext context)
        {
            VerificationResult result = policy.Verify(context);

            if (!data.VerificationResultMatch(result.VerificationError))
            {
                Assert.Fail("Unexpected verification result: " + (result.VerificationError == null ? "OK" : result.VerificationError.Code) + "; Expected result: " +
                            data.ErrorCode);
            }
        }

        public static TestingRow[] GetInvalidSignatureTestData()
        {
            return GetSignatureTestData(InvalidSignatureDir + "invalid-signature-results.csv");
        }

        public static TestingRow[] GetValidSignatureTestData()
        {
            return GetSignatureTestData(ValidSignatureDir + "signature-results.csv");
        }

        public static TestingRow[] GetInternalPolicyVerificationSignatureTestData()
        {
            return GetSignatureTestData(InternalPolicyVerificationDir + "internal-policy-results.csv");
        }

        public static TestingRow[] GetPolicyVerificationSignatureTestData()
        {
            return GetSignatureTestData(PolicyVerificationDir + "policy-verification-results.csv");
        }

        public static TestingRow[] GetSignatureTestData(string dataFilePath)
        {
            List<TestingRow> list = new List<TestingRow>();
            int i = 0;

            foreach (string row in File.ReadAllLines(Path.Combine(TestSetup.LocalPath, dataFilePath)))
            {
                if (i == 0)
                {
                    i++;
                    continue;
                }

                list.Add(new TestingRow(row, i++));
            }

            return list.ToArray();
        }

        private static IPublicationsFile PubsFile => _pubsFile ?? (_pubsFile = IntegrationTests.GetHttpKsiService().GetPublicationsFile());

        private static IPublicationsFile GetPublicationsFile(string path, string certPath)
        {
            if (string.IsNullOrEmpty(path))
            {
                return PubsFile;
            }

            X509Store certStore = string.IsNullOrEmpty(certPath) ? new X509Store(StoreName.Root) : TestUtil.CreateCertStore(certPath);

            PublicationsFileFactory factory = new PublicationsFileFactory(
                new PkiTrustStoreProvider(certStore, CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com")));

            return factory.Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, path)));
        }

        public class TestingRow
        {
            public TestingRow(string row, int index)
            {
                string[] args = row.Split(';');

                FileName = args[0];
                ActionName = args[1];
                ErrorCode = args[2];
                ErrorMessage = args[3];
                InputHashLevel = !string.IsNullOrEmpty(args[4]) ? uint.Parse(args[4]) : 0;

                string s = args[5];
                if (!string.IsNullOrEmpty(s))
                {
                    InputHash = new DataHash(Base16.Decode(s));
                }

                s = args[6];
                if (!string.IsNullOrEmpty(s))
                {
                    CalendarHashChainInput = new DataHash(Base16.Decode(s));
                }

                s = args[7];
                if (!string.IsNullOrEmpty(s))
                {
                    CalendarHashChainOutput = new DataHash(Base16.Decode(s));
                }

                s = args[8];
                if (!string.IsNullOrEmpty(s))
                {
                    AggregationTime = ulong.Parse(s);
                }

                s = args[9];
                if (!string.IsNullOrEmpty(s))
                {
                    PublicationTime = ulong.Parse(s);
                }

                s = args[10];
                if (!string.IsNullOrEmpty(s))
                {
                    PublicationData = new PublicationData(s);
                }

                s = args[11];
                if (!string.IsNullOrEmpty(s) && s.ToUpper() == "TRUE")
                {
                    IsExtendingAllowed = true;
                }

                ResourceFile = args[12];
                PublicationsFilePath = args[13];
                CertFilePath = args[14];
                TestIndex = index;
            }

            public int TestIndex { get; }
            public string FileName { get; }
            public string ActionName { get; }
            public string ErrorCode { get; }
            public string ErrorMessage { get; }
            public uint InputHashLevel { get; }
            public DataHash InputHash { get; }
            public DataHash CalendarHashChainInput { get; }
            public DataHash CalendarHashChainOutput { get; }
            public ulong AggregationTime { get; }
            public ulong PublicationTime { get; }
            public PublicationData PublicationData { get; }
            public bool IsExtendingAllowed { get; }
            public string ResourceFile { get; }
            public string PublicationsFilePath { get; }
            public string CertFilePath { get; }

            public bool VerificationResultMatch(VerificationError verificationError)
            {
                if (verificationError == null)
                {
                    return string.IsNullOrEmpty(ErrorCode);
                }

                if (ErrorCode == verificationError.Code)
                {
                    return true;
                }

                return false;
            }

            public override string ToString()
            {
                return TestIndex + ": " + ActionName + ": " + FileName;
            }
        }
    }
}