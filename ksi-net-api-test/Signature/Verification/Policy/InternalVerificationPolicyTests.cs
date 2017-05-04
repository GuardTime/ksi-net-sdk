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

using System.IO;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Test.Signature.Verification.Rule;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Policy
{
    [TestFixture]
    public class InternalVerificationPolicyTests
    {
        [Test]
        public void InternalVerificationPolicyOkTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                    DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"))
                };

                VerificationResult verificationResult = policy.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void InternalVerificationPolicyDocumentHashTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                    DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772E"))
                };

                VerificationResult verificationResult = policy.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Gen01, verificationResult.VerificationError);
            }
        }

        [Test]
        public void InternalVerificationPolicyDocumentHashLevelTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                    DocumentHashLevel = 1,
                    DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"))
                };

                VerificationResult verificationResult = policy.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Gen03, verificationResult.VerificationError);
            }
        }

        [Test]
        public void InternalVerificationPolicyAggregationChainInputHashTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Legacy_Invalid_Input), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                };

                VerificationResult verificationResult = policy.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Int01, verificationResult.VerificationError);
            }
        }

        [Test]
        public void InternalVerificationPolicyRfc3161RecordAggregationTimeTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Invalid_Rfc3161_Aggregation_Time_Mismatch), FileMode.Open)
                )
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                };

                VerificationResult verificationResult = policy.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Int02, verificationResult.VerificationError);
            }
        }

        [Test]
        public void InternalVerificationPolicyRfc3161RecordChainIndexTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Invalid_Rfc3161_Chain_Index_Mismatch), FileMode.Open)
                )
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                };

                VerificationResult verificationResult = policy.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Int12, verificationResult.VerificationError);
            }
        }

        [Test]
        public void InternalVerificationPolicyAggregationHashChainIndexSuccessorTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            using (
                FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Invalid_Aggregation_Chain_Index_Mismatch_Prev), FileMode.Open)
                )
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                };

                VerificationResult verificationResult = policy.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Int12, verificationResult.VerificationError);
            }
        }

        [Test]
        public void InternalVerificationPolicyAggregationHashChainMetadataTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.AggregationHashChainMetadataPaddingNotFirstFail), FileMode.Open))
            };

            VerificationResult verificationResult = policy.Verify(context);
            Assert.AreEqual(VerificationError.Int11.Code, verificationResult.VerificationError?.Code);
        }

        [Test]
        public void InternalVerificationPolicyAggregationHashChainConsistencyTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.KsiSignature_Invalid_Aggregation_Chain_Input_Hash), FileMode.Open))
            };

            VerificationResult verificationResult = policy.Verify(context);
            Assert.AreEqual(VerificationError.Int01.Code, verificationResult.VerificationError?.Code);
        }

        [Test]
        public void InternalVerificationPolicyAggregationHashChainTimeConsistencyTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.KsiSignature_Invalid_Aggregation_Chain_Aggregation_Time_Mismatch), FileMode.Open))
            };

            VerificationResult verificationResult = policy.Verify(context);
            Assert.AreEqual(VerificationError.Int02.Code, verificationResult.VerificationError?.Code);
        }

        [Test]
        public void InternalVerificationPolicyAggregationHashChainIndexTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.KsiSignature_Invalid_Aggregation_Chain_Index_Mismatch), FileMode.Open))
            };

            VerificationResult verificationResult = policy.Verify(context);
            Assert.AreEqual(VerificationError.Int10.Code, verificationResult.VerificationError?.Code);
        }

        [Test]
        public void InternalVerificationPolicyCalendarHashChainInputHashVerificationTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.KsiSignature_Invalid_Calendar_Chain_Input_Hash), FileMode.Open))
            };

            VerificationResult verificationResult = policy.Verify(context);
            Assert.AreEqual(VerificationError.Int03.Code, verificationResult.VerificationError?.Code);
        }

        [Test]
        public void InternalVerificationPolicyCalendarHashChainAggregationTimeTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.KsiSignature_Invalid_Calendar_Chain_Publication_Time), FileMode.Open))
            };

            VerificationResult verificationResult = policy.Verify(context);
            Assert.AreEqual(VerificationError.Int04.Code, verificationResult.VerificationError?.Code);
        }

        [Test]
        public void InternalVerificationPolicyCalendarHashChainRegistrationTimeTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.KsiSignature_Invalid_Calendar_Chain_Registration_Time), FileMode.Open))
            };

            VerificationResult verificationResult = policy.Verify(context);
            Assert.AreEqual(VerificationError.Int05.Code, verificationResult.VerificationError?.Code);
        }

        [Test]
        public void InternalVerificationPolicyCalendarAuthenticationRecordAggregationHashTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.KsiSignature_Invalid_Calendar_Authentication_Record_Invalid_Publication_Hash), FileMode.Open))
            };

            VerificationResult verificationResult = policy.Verify(context);
            Assert.AreEqual(VerificationError.Int08.Code, verificationResult.VerificationError?.Code);
        }

        [Test]
        public void InternalVerificationPolicyCalendarAuthenticationRecordAggregationTimeTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.KsiSignature_Invalid_Calendar_Authentication_Record_Invalid_Publication_Time), FileMode.Open))
            };

            VerificationResult verificationResult = policy.Verify(context);
            Assert.AreEqual(VerificationError.Int06.Code, verificationResult.VerificationError?.Code);
        }

        [Test]
        public void InternalVerificationPolicySignaturePublicationRecordPublicationHashTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.KsiSignature_Invalid_With_Invalid_Publication_Record_Hash), FileMode.Open))
            };

            VerificationResult verificationResult = policy.Verify(context);
            Assert.AreEqual(VerificationError.Int09.Code, verificationResult.VerificationError?.Code);
        }

        [Test]
        public void InternalVerificationPolicySignaturePublicationRecordPublicationTimeTest()
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature =
                    new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(new FileStream(Path.Combine(TestSetup.LocalPath,
                        Properties.Resources.KsiSignature_Invalid_With_Invalid_Publication_Record_Time), FileMode.Open))
            };

            VerificationResult verificationResult = policy.Verify(context);
            Assert.AreEqual(VerificationError.Int07.Code, verificationResult.VerificationError?.Code);
        }
    }
}