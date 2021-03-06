﻿/*
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

using System.IO;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    [TestFixture]
    public class LegacyPduTests : StaticServiceTestsBase
    {
        /// <summary>
        /// Test Legacy PDU MAC calculation. MAC is valid.
        /// </summary>
        [Test]
        public void LegacyPduMacCalcTest()
        {
            byte[] bytes = File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_LegacyAggregationResponsePdu));

            ImprintTag mac;

            using (TlvReader tlvReader = new TlvReader(new MemoryStream(bytes)))
            {
                mac = new LegacyAggregationPdu(tlvReader.ReadTag()).Mac;
            }

            Assert.IsTrue(LegacyPdu.ValidateMac(bytes, mac, Util.EncodeNullTerminatedUtf8String(TestConstants.ServicePass)), "MAC should be valid");
        }

        /// <summary>
        /// Test Legacy PDU MAC calculation. MAC is invalid.
        /// </summary>
        [Test]
        public void LegacyPduMacCalcInvalidTest()
        {
            byte[] bytes = File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_LegacyAggregationResponsePdu));

            ImprintTag mac = new ImprintTag(0x1, false, false,
                new DataHash(HashAlgorithm.Sha2256,
                    new byte[]
                    {
                        0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                        0x28, 0x29, 0x30, 0x31, 0x32
                    }));

            Assert.IsFalse(LegacyPdu.ValidateMac(bytes, mac, Util.EncodeNullTerminatedUtf8String(TestConstants.ServicePass)), "MAC should be invalid");
        }

        /// <summary>
        /// Test Legacy PDU MAC calculation. PDU contains a value 0x0 representing an integer. MAC is valid.
        /// </summary>
        [Test]
        public void LegacyPduMacCalcWith0x0IntStaticTest()
        {
            byte[] bytes = File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_LegacyAggregationResponsePdu_0x0_Int));

            ImprintTag mac;

            using (TlvReader tlvReader = new TlvReader(new MemoryStream(bytes)))
            {
                mac = new LegacyAggregationPdu(tlvReader.ReadTag()).Mac;
            }

            Assert.IsTrue(LegacyPdu.ValidateMac(bytes, mac, Util.EncodeNullTerminatedUtf8String(TestConstants.ServicePass)), "MAC should be valid");
        }

        /// <summary>
        /// Test Legacy PDU MAC calculation. PDU contains a value 0x0 representing an integer but it is converted to an empty TLV. MAC is invalid.
        /// </summary>
        [Test]
        public void LegacyPduMacCalcWith0x0IntStaticInvalidTest()
        {
            byte[] bytes = File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_LegacyAggregationResponsePdu_0x0_Int));

            LegacyAggregationPdu pdu;

            using (TlvReader tlvReader = new TlvReader(new MemoryStream(bytes)))
            {
                pdu = new LegacyAggregationPdu(tlvReader.ReadTag());
            }

            // 0x0 value representing an integer is converted to an empty TLV, thus MAC check will fail.
            byte[] pduBytes = pdu.Encode();
            Assert.IsFalse(LegacyPdu.ValidateMac(pduBytes, pdu.Mac, Util.EncodeNullTerminatedUtf8String(TestConstants.ServicePass)), "MAC should be invalid");
        }
    }
}