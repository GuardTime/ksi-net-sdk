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
using System.Reflection;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class CalendarHashChainAlgorithmObsoleteRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            CalendarHashChainAlgorithmObsoleteRule rule = new CalendarHashChainAlgorithmObsoleteRule();

            // Argument null exception when no context
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                rule.Verify(null);
            });
            Assert.AreEqual("context", ex.ParamName);
        }

        [Test]
        public void TestContextMissingSignature()
        {
            CalendarHashChainAlgorithmObsoleteRule rule = new CalendarHashChainAlgorithmObsoleteRule();

            // Verification exception on missing KSI signature 
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();
                rule.Verify(context);
            });
            Assert.That(ex.Message, Does.StartWith("Invalid KSI signature in context: null"));
        }

        [Test]
        public void TestOkAlgorithms()
        {
            CalendarHashChainAlgorithmObsoleteRule rule = new CalendarHashChainAlgorithmObsoleteRule();

            // Check with calendar hash chains that use hash algorithms without obsolete date
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestOkAlgorithmBeforeObsoleteDate()
        {
            AddObsoleteAlgorithm();

            CalendarHashChainAlgorithmObsoleteRule rule = new CalendarHashChainAlgorithmObsoleteRule();

            // Check with calendar hash chains that use hash algorithms with obsolete date and publication time is before obsolete date
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Obsolete_Calendar_Chain_Algorithm_2016), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestInvalidAlgorithmAfterObsoleteDate()
        {
            AddObsoleteAlgorithm();

            CalendarHashChainAlgorithmObsoleteRule rule = new CalendarHashChainAlgorithmObsoleteRule();

            // Check with calendar hash chains that use hash algorithms with obsolete date and publication time is after obsolete date
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Obsolete_Calendar_Chain_Algorithm_2017), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Int16, verificationResult.VerificationError);
            }
        }

        private static void AddObsoleteAlgorithm()
        {
            const int id = 0x7d;
            if (HashAlgorithm.GetById(id) != null)
            {
                return;
            }

            Type type = typeof(HashAlgorithm);
            FieldInfo info = type.GetField("Values", BindingFlags.NonPublic | BindingFlags.Static);

            if (info == null)
            {
                throw new Exception("Cannot get static variable Values from HashAlgorithm.");
            }

            HashAlgorithm[] values = (HashAlgorithm[])info.GetValue(null);

            Type[] paramTypes = new Type[] { typeof(string), typeof(byte), typeof(int), typeof(HashAlgorithm.AlgorithmStatus), typeof(string[]), typeof(ulong?), typeof(ulong?) };

            object[] paramValues = new object[] { "TEST_ALGO", (byte)id, 10, HashAlgorithm.AlgorithmStatus.Normal, null, (ulong?)1467331200, (ulong?)1467331200 };

            Type t = typeof(HashAlgorithm);

            ConstructorInfo ci = t.GetConstructor(
                BindingFlags.Instance | BindingFlags.NonPublic,
                null, paramTypes, null);

            HashAlgorithm testHashAlgorithm = (HashAlgorithm)ci.Invoke(paramValues);

            List<HashAlgorithm> list = new List<HashAlgorithm>(values) { testHashAlgorithm };

            info.SetValue(null, list.ToArray());
        }
    }
}