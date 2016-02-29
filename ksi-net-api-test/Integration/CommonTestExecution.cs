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
using System.IO;
using System.Linq;
using Guardtime.KSI.Publication;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;

using Guardtime.KSI.Trust;
using NUnit.Framework;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Integration
{
    public class CommonTestExecution
    {
        public void TestExecution(DataHolderForIntegrationTests testData, string policyName)
        {
            Console.WriteLine(string.Format("Running test with the following data: " + testData.GetTestDataInformation() + "; Policy: " + policyName));
            using (FileStream stream = new FileStream(testData.GetTestFile(), FileMode.Open)) { 
                try
                {

                    IKsiSignature signature = new KsiSignatureFactory().Create(stream);
                    Assert.IsFalse(testData.GetSigantureReadInFails(), testData.GetTestFile() + " supposed to fail with class " + testData.GetExpectedExceptionClass() + " exception.");
                    VerificationContext context = new VerificationContext(signature);

                    VerificationPolicy policy;

                    switch (policyName)
                    {
                        case "PublicationFileBasedVerificationPolicy":
                            using (Stream publicationFileInStream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
                            {
                                policy = new PublicationBasedVerificationPolicy();
                                context.PublicationsFile = new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                                    new CertificateSubjectRdnSelector(new List<CertificateSubjectRdn>
                                    {
                                        new CertificateSubjectRdn("1.2.840.113549.1.9.1", "publications@guardtime.com")
                                    })))
                                    .Create(publicationFileInStream);
                                context.IsExtendingAllowed = true;
                                context.KsiService = IntegrationTests.GetHttpKsiService();
                                break;
                            }

                        case "PublicationFileBasedVerificationNoExtendingPolicy":
                            using (Stream publicationFileInStream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
                            {
                                policy = new PublicationBasedVerificationPolicy();
                                context.PublicationsFile = new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                                    new CertificateSubjectRdnSelector(new List<CertificateSubjectRdn>
                                    {
                                        new CertificateSubjectRdn("1.2.840.113549.1.9.1", "publications@guardtime.com")
                                    })))
                                    .Create(publicationFileInStream);
                                context.IsExtendingAllowed = false;
                                break;
                            }

                        case "KeyBasedVerificationPolicyWithNoPublication":
                            policy = new KeyBasedVerificationPolicy(new X509Store(StoreName.Root),
                                new CertificateSubjectRdnSelector(new List<CertificateSubjectRdn>
                                {
                                    new CertificateSubjectRdn("1.2.840.113549.1.9.1", "publications@guardtime.com")
                                }));
                            break;

                        case "PublicationStringBasedVerificationPolicy":
                            policy = new PublicationBasedVerificationPolicy();
                            context.UserPublication = new PublicationData("AAAAAA-CWYEKQ-AAIYPA-UJ4GRT-HXMFBE-OTB4AB-XH3PT3-KNIKGV-PYCJXU-HL2TN4-RG6SCC-3ZGSBM");
                            context.IsExtendingAllowed = true;
                            context.KsiService = IntegrationTests.GetHttpKsiService();
                            break;

                        case "PublicationStringBasedVerificationNoExtendingPolicy":
                            policy = new PublicationBasedVerificationPolicy();
                            context.UserPublication = new PublicationData("AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUACP-GOGD6K");
                            context.KsiService = IntegrationTests.GetHttpKsiService();
                            break;

                        case "PublicationStringBasedVerificationUsingOldStringPolicy":
                            policy = new PublicationBasedVerificationPolicy();
                            context.UserPublication = new PublicationData("AAAAAA-CS2XHY-AAJCBE-DDAFMR-R3RKMY-GMAQDZ-FSAE7B-ZO64CT-QPNC3B-RQ6UGY-67QORK-6STDTS");
                            context.IsExtendingAllowed = true;
                            context.KsiService = IntegrationTests.GetHttpKsiService();
                            break;

                        case "CalendarBasedVerificationPolicy":
                            policy = new CalendarBasedVerificationPolicy();
                            context.IsExtendingAllowed = true;
                            context.KsiService = IntegrationTests.GetHttpKsiService();
                            break;

                        default:
                            using (Stream publicationFileInStream = new FileStream("resources/publication/publicationsfile/ksi-publications.bin", FileMode.Open))
                            {
                                policy = new KeyBasedVerificationPolicy(new X509Store(StoreName.Root),
                                new CertificateSubjectRdnSelector(new List<CertificateSubjectRdn>
                                {
                                    new CertificateSubjectRdn("1.2.840.113549.1.9.1", "publications@guardtime.com")
                                }));
                                context.PublicationsFile = new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                                        new CertificateSubjectRdnSelector(new List<CertificateSubjectRdn>
                                        {
                                        new CertificateSubjectRdn("1.2.840.113549.1.9.1", "publications@guardtime.com")
                                        })))
                                        .Create(publicationFileInStream);
                                break;
                            }
                    }

                    VerificationResult verificationResult = policy.Verify(context);

                    string expectedResults = testData.GetExpectedVerificationResultCode().ToLower();
                    if (expectedResults.Equals(verificationResult.ResultCode.ToString().ToLower()))
                    {
                        if (expectedResults.Equals("ok"))
                        {
                            return;
                        }
                        bool ruleFound = false;
                        foreach (string rule in verificationResult.ToString().Split(new string[] { Environment.NewLine }, StringSplitOptions.None).Where(rule => rule.ToLower().Contains(testData.GetExpectedRule().ToLower())))
                        {
                            if (!(rule.Split(':')[1].ToLower().Contains(expectedResults.ToLower())))
                            {
                                throw new Exception(
                                    string.Format("Expected rule '" + testData.GetExpectedRule() + "' results to be '" + testData.GetExpectedVerificationResultCode() +
                                                    "', but found: " + rule));
                            }
                            ruleFound = true;
                        }
                        if (!ruleFound)
                        {
                            throw new Exception(string.Format("Expected rule '" + testData.GetExpectedRule() + "' was not found from verification results:" + verificationResult));
                        }
                    }
                    else
                    {
                        Assert.IsTrue(verificationResult.ResultCode.ToString().ToLower() == testData.GetExpectedVerificationResultCode().ToLower(), "Verification codes do not match. Actual '" +
                        verificationResult.ResultCode + "' and expected '" +
                        testData.GetExpectedVerificationResultCode() + "'.");
                    }
                }
                catch (Exception e)
                {
                    //If failure occurs with test that should not fail at all.
                    if (testData.GetExpectedVerificationResultCode().ToLower().Equals("ok"))
                    {
                        throw;
                    }
                    //Errors that were found duing executiong and evaluation.
                    if (e.ToString().Contains(" supposed to fail with class ") || 
                        e.ToString().Contains(", but found: ") ||
                        e.ToString().Contains(" was not found from verification results:") ||
                        e.ToString().Contains("Verification codes do not match. Actual ")
                        )
                    {
                        throw;
                    }

                    //Signature read in did not fail while it should have.
                    //No failure during readin AND exception does not contain expected (message OR exception class OR rule)
                    //which means that not expected error has occurred.
                    string exceptionString = e.ToString().ToLower();
                    if ( testData.GetExpectedExceptionMessage() != " " && !exceptionString.Contains(testData.GetExpectedExceptionMessage().ToLower()) ||
                        testData.GetExpectedExceptionClass() != " " && !exceptionString.Contains(testData.GetExpectedExceptionClass().ToLower()) ||
                        testData.GetExpectedRule() != " " && !exceptionString.Contains(testData.GetExpectedRule().ToLower()))
                    {
                        throw;
                    }
                }
            }
        }
    }
}
