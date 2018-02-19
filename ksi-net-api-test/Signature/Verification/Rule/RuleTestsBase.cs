/*
 * Copyright 2013-2018 Guardtime, Inc.
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
using System.Collections.ObjectModel;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Test.Publication;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    public abstract class RuleTestsBase
    {
        public abstract VerificationRule Rule { get; }

        // The tests defined here are not run by nunit adapter if you run tests in a specific file.

        [Test]
        public virtual void TestMissingContext()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                Rule.Verify(null);
            }, "Exception expected but non thrown. Rule: " + Rule);
            Assert.AreEqual("context", ex.ParamName);
        }

        /// <summary>
        /// Verification exception on missing KSI signature 
        /// </summary>
        [Test]
        public virtual void TestContextMissingSignature()
        {
            TestContextMissingSignature(new TestVerificationContext());
        }

        /// <summary>
        /// Verification exception on missing KSI signature 
        /// </summary>
        public void TestContextMissingSignature(TestVerificationContext context)
        {
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                Rule.Verify(context);
            }, "Exception expected but non thrown. Rule: " + Rule);
            Assert.That(ex.Message, Does.StartWith("Invalid KSI signature in context: null"), "Unexpected exception message. Rule: " + Rule);
        }

        /// <summary>
        /// Verification exception on missing publications file
        /// </summary>
        public void TestContextMissingPublicationsFile(IKsiSignature signature = null)
        {
            TestVerificationContext context = new TestVerificationContext(signature ?? TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record));
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                Rule.Verify(context);
            });
            Assert.That(ex.Message, Does.StartWith("Invalid publications file in context: null"));
        }

        /// <summary>
        /// Verification exception on missing publications file
        /// </summary>
        public void TestContextMissingUserPublication(IKsiSignature signature = null)
        {
            TestVerificationContext context = new TestVerificationContext(signature ?? TestUtil.GetSignature());
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                Rule.Verify(context);
            });
            Assert.That(ex.Message, Does.StartWith("Invalid user publication in context: null"));
        }

        /// <summary>
        /// Verification exception on missing KSI signature aggregation hash chain 
        /// </summary>
        public void TestSignatureMissingAggregationHashChain(IKsiSignature signature = null, bool expectSuccess = false)
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = signature ?? new TestKsiSignature() { AggregationHashChains = new ReadOnlyCollection<AggregationHashChain>(new AggregationHashChain[] { }) }
            };

            if (expectSuccess)
            {
                Verify(context, VerificationResultCode.Ok);
            }
            else
            {
                DoesThrow<KsiVerificationException>(delegate
                {
                    Rule.Verify(context);
                }, "Aggregation hash chains are missing from KSI signature");
            }
        }

        /// <summary>
        /// Verification exception on missing KSI signature calendar hash chain 
        /// </summary>
        public void TestSignatureMissingCalendarHashChain(IKsiSignature signature)
        {
            TestSignatureMissingCalendarHashChain(new TestVerificationContext(signature));
        }

        /// <summary>
        /// Verification exception on missing KSI signature calendar hash chain 
        /// </summary>
        public void TestSignatureMissingCalendarHashChain(IVerificationContext context)
        {
            DoesThrow<KsiVerificationException>(delegate
            {
                Rule.Verify(context);
            }, "Calendar hash chain is missing from KSI signature");
        }

        /// <summary>
        /// Verification exception on missing KSI signature calendar authentication record 
        /// </summary>
        public void TestSignatureMissingCalendarAuthRecord(IVerificationContext context)
        {
            DoesThrow<KsiVerificationException>(delegate
            {
                Rule.Verify(context);
            }, "Calendar authentication record in missing from KSI signature");
        }

        /// <summary>
        /// Verification exception on missing KSI signature publication record 
        /// </summary>
        public virtual void TestSignatureMissingPublicationRecord(IVerificationContext context = null)
        {
            DoesThrow<KsiVerificationException>(delegate
            {
                Rule.Verify(context ?? new TestVerificationContext(TestUtil.GetSignature()));
            }, "Publication record is missing from KSI signature");
        }

        /// <summary>
        /// Check invalid extended calendar chain returned by context extension function
        /// </summary>
        /// <param name="context"></param>
        public void TestSignatureWithInvalidContextExtendFunctions(IVerificationContext context = null)
        {
            DoesThrow<KsiVerificationException>(delegate
            {
                Rule.Verify(context ?? new TestVerificationContext()
                {
                    Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Publication_Record)
                });
            }, "Received invalid extended calendar hash chain from context extension function: null");
        }

        protected void DoesThrow<T>(TestDelegate code, string expectedMessageStart) where T : Exception
        {
            T ex = Assert.Throws<T>(code);
            Assert.That(ex.Message, Does.StartWith(expectedMessageStart));
        }

        protected void CreateSignatureAndVerify(string signaturePath, VerificationResultCode expectedResultCode, VerificationError expectedVerificationError = null)
        {
            CreateSignatureAndVerify(signaturePath, null, expectedResultCode, expectedVerificationError);
        }

        protected void CreateSignatureAndVerify(string signaturePath, DataHash documentHash, VerificationResultCode expectedResultCode,
                                                VerificationError expectedVerificationError = null)
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(signaturePath),
                DocumentHash = documentHash
            };

            Verify(context, expectedResultCode, expectedVerificationError);
        }

        protected void Verify(IVerificationContext context, VerificationResultCode expectedResultCode, VerificationError expectedVerificationError = null)
        {
            VerificationResult verificationResult = Rule.Verify(context);
            Assert.AreEqual(expectedResultCode, verificationResult.ResultCode, "Unexpected verification result code");
            if (expectedResultCode == VerificationResultCode.Fail)
            {
                Assert.AreEqual(expectedVerificationError?.Code, verificationResult.VerificationError.Code, "Unexpected verification error code");
            }
        }

        protected static TestPublicationsFile GetPublicationsFile(ulong searchByTime, ulong publicationTime, string encodedPublicationHash)
        {
            TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
            testPublicationsFile.NearestPublications.Add(searchByTime,
                new PublicationRecordInPublicationFile(new RawTag(0x703, false, false,
                    new PublicationData(publicationTime, new DataHash(Base16.Decode(encodedPublicationHash))).Encode())));
            return testPublicationsFile;
        }
    }
}