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
using System.Reflection;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class CalendarHashChainAlgorithmObsoleteRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new CalendarHashChainAlgorithmObsoleteRule();

        [Test]
        public void TestSignatureMissingCalendarHashChain()
        {
            // Check signature without calendar chain
            CreateSignatureAndVerify(Resources.KsiSignature_Ok_AggregationHashChain_Only, VerificationResultCode.Ok);
        }

        [Test]
        public void TestOkAlgorithms()
        {
            // Check with calendar hash chains that use hash algorithms without obsolete date
            CreateSignatureAndVerify(Resources.KsiSignature_Ok, VerificationResultCode.Ok);
        }

        [Test]
        public void TestOkAlgorithmBeforeObsoleteDate()
        {
            AddObsoleteAlgorithm();

            // Check with calendar hash chains that use hash algorithms with obsolete date and publication time is before obsolete date
            CreateSignatureAndVerify(Resources.KsiSignature_Obsolete_Calendar_Chain_Algorithm_2016, VerificationResultCode.Ok);
        }

        [Test]
        public void TestInvalidAlgorithmAfterObsoleteDate()
        {
            AddObsoleteAlgorithm();

            // Check with calendar hash chains that use hash algorithms with obsolete date and publication time is after obsolete date
            CreateSignatureAndVerify(Resources.KsiSignature_Obsolete_Calendar_Chain_Algorithm_2017, VerificationResultCode.Fail, VerificationError.Int16);
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

            Type[] paramTypes = new Type[] { typeof(string), typeof(byte), typeof(int), typeof(HashAlgorithm.AlgorithmStatus), typeof(string[]), typeof(ulong?), typeof(ulong?) };
            ConstructorInfo ci = typeof(HashAlgorithm).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic, null, paramTypes, null);

            if (ci == null)
            {
                throw new Exception("Cannot get HashAlgorithm constuctor.");
            }

            HashAlgorithm[] values = (HashAlgorithm[])info.GetValue(null);
            object[] paramValues = new object[] { "TEST_ALGO", (byte)id, 10, HashAlgorithm.AlgorithmStatus.Normal, null, (ulong?)1467331200, (ulong?)1467331200 };
            HashAlgorithm testHashAlgorithm = (HashAlgorithm)ci.Invoke(paramValues);
            List<HashAlgorithm> list = new List<HashAlgorithm>(values) { testHashAlgorithm };
            info.SetValue(null, list.ToArray());
        }
    }
}