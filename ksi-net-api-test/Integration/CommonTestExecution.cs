using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Guardtime.KSI.Publication;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Service;
using Guardtime.KSI.Trust;
using NUnit.Framework;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Signature.Verification.Rule;

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
                            using (Stream publicationFileInStream = new FileStream("resources/publication/publicationsfile/newest-ksi-publications.bin", FileMode.Open))
                            {
                                policy = new PublicationBasedVerificationPolicy();
                                context.PublicationsFile = new PublicationsFileFactory(new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                                    new CertificateSubjectRdnSelector(new List<CertificateSubjectRdn>
                                    {
                                        new CertificateSubjectRdn("1.2.840.113549.1.9.1", "publications@guardtime.com")
                                    })))
                                    .Create(publicationFileInStream);
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
                            context.UserPublication = new PublicationData("AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUBD7-OE44VA");
                            break;

                        case "CalendarBasedVerificationPolicy":
                            policy = new CalendarBasedVerificationPolicy();
                            context.IsExtendingAllowed = true;
                            context.KsiService = IntegrationTests.GetHttpKsiService();
                            break;

                        default:
                            using (Stream publicationFileInStream = new FileStream("resources/publication/publicationsfile/newest-ksi-publications.bin", FileMode.Open))
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
                    Console.WriteLine(string.Format("Result start:"));
                    Console.WriteLine(verificationResult);
                    Console.WriteLine(string.Format("Result end"));

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
                    Console.WriteLine(string.Format("E start:"));
                    Console.WriteLine(e);
                    Console.WriteLine(string.Format("E end"));
                    if (testData.GetSigantureReadInFails() &&
                        e.ToString().Contains(" supposed to fail with class ") ||
                        !testData.GetSigantureReadInFails()
                        )
                    {
                        throw;
                    }
                }
            }
        }
    }
}
