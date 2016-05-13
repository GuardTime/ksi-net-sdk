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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.MultiSignature;
using Guardtime.KSI.Test.Integration;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature
{
    [TestFixture]
    public class KsiMultiSignatureTests
    {
        // TODO: test for removing when same round signatures but different aggregators

        /// <summary>
        /// Test loading multi-signature with invalid magic bytes.
        /// </summary>
        [Test]
        public void MultiSignatureLoadInvalidHeaderTest()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok), FileMode.Open))
            {
                Assert.That(delegate
                {
                    new KsiMultiSignature(stream, new KsiSignatureFactory());
                }, Throws.TypeOf<KsiMultiSignatureException>().With.Message.StartWith("Invalid multi-signature magic bytes"));
            }
        }

        /// <summary>
        /// Test creating mult-signature. Validates that input and output signatures are equal (contain same tags with same values)
        /// </summary>
        [Test]
        public void MultiSignatureCreateTest()
        {
            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok);
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok_New);

            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory());

            multiSignature.Add(signature1);
            multiSignature.Add(signature2);

            IKsiSignature outSig1 = multiSignature.Get(signature1.GetAggregationHashChains()[0].InputHash);
            IKsiSignature outSig2 = multiSignature.Get(signature2.GetAggregationHashChains()[0].InputHash);

            bool areEqual = AreEqual((KsiSignature)signature1, (KsiSignature)outSig1);
            if (!areEqual)
            {
                Console.WriteLine("First signatures do not match");
                Console.WriteLine("Signature in: " + signature1);
                Console.WriteLine("Signature out: " + outSig1);
                Assert.Fail("First signatures do not match");
            }

            areEqual = AreEqual((KsiSignature)signature2, (KsiSignature)outSig2);
            if (!areEqual)
            {
                Console.WriteLine("Second signatures do not match");
                Console.WriteLine("Signature in: " + signature2);
                Console.WriteLine("Signature out: " + outSig2);
                Assert.Fail("Second signatures do not match");
            }
        }

        /// <summary>
        /// Test adding legacy signature.
        /// </summary>
        [Test]
        public void MultiSignatureAddLegacySignatureTest()
        {
            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok);
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Legacy_Ok);

            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory());

            multiSignature.Add(signature1);
            multiSignature.Add(signature2);

            IKsiSignature outSig1 = multiSignature.Get(signature1.GetAggregationHashChains()[0].InputHash);
            IKsiSignature outSig2 = multiSignature.Get(signature2.Rfc3161Record.InputHash);

            bool areEqual = AreEqual((KsiSignature)signature1, (KsiSignature)outSig1);
            if (!areEqual)
            {
                Console.WriteLine("First signatures do not match");
                Console.WriteLine("Signature in: " + signature1);
                Console.WriteLine("Signature out: " + outSig1);
                Assert.Fail("First signatures do not match");
            }

            areEqual = AreEqual((KsiSignature)signature2, (KsiSignature)outSig2);
            if (!areEqual)
            {
                Console.WriteLine("Second signatures do not match");
                Console.WriteLine("Signature in: " + signature2);
                Console.WriteLine("Signature out: " + outSig2);
                Assert.Fail("Second signatures do not match");
            }
        }

        /// <summary>
        /// Test creating multi-signature with same signature being un-extended and extended.
        /// </summary>
        [Test]
        public void MultiSignatureCreateWithSameSignatureUnextendedAndExtendedTest()
        {
            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok);
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok_Extended);

            Assert.AreEqual(signature1.GetAggregationHashChains()[0].InputHash, signature2.GetAggregationHashChains()[0].InputHash,
                "Document hash in first and third signature should be equal");

            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory());

            multiSignature.Add(signature1);
            multiSignature.Add(signature2);

            //multiSignature.Add(GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Legacy_Ok));
            //multiSignature.Add(GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMulti_sha2_384));
            //multiSignature.Add(GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok_Extended));
            //multiSignature.Add(GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMulti_sha2_512));
            //multiSignature.Add(GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMulti_20150528_Ok));

            IKsiSignature outSig1 = multiSignature.Get(signature1.GetAggregationHashChains()[0].InputHash);

            bool areEqual = AreEqual((KsiSignature)signature2, (KsiSignature)outSig1);
            if (!areEqual)
            {
                Console.WriteLine("First signature does not match");
                Console.WriteLine("Signature in: " + signature2);
                Console.WriteLine("Signature out: " + outSig1);
                Assert.Fail("First signatures do not match");
            }

            ITlvTag[] tags = multiSignature.GetAllTags();

            Assert.AreEqual(5, tags.Count(t => t is AggregationHashChain), "Aggregation hash chain count does not match");
            Assert.AreEqual(1, multiSignature.GetUsedHashAlgorithms().Length, "Invalid used hash algorithm count.");
            Assert.AreEqual(1, tags.Count(t => t is CalendarHashChain), "Calendar hash chain count does not match");
            Assert.AreEqual(0, tags.Count(t => t is CalendarAuthenticationRecord), "Calendar authentication record count does not match");
            Assert.AreEqual(1, tags.Count(t => t is PublicationRecordInSignature), "Publication record count does not match");
            Assert.AreEqual(0, tags.Count(t => t is Rfc3161Record), "Rfc3161 record count does not match");

            //using (FileStream stream = File.Create(@"c:\temp\multi-signature-5.tlv"))
            //{
            //    multiSignature.WriteTo(stream);
            //}
        }

        /// <summary>
        /// Test adding signatures from the same aggregation round.
        /// </summary>
        [Test]
        public void MultiSignatureAddUniSignaturesFromSameAggregationRoundToContainerTest()
        {
            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory());

            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMultiSameAggregationRound_1_Ok);
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMultiSameAggregationRound_2_Ok);
            IKsiSignature signature3 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMultiSameAggregationRound_3_Ok);

            multiSignature.Add(signature1);
            multiSignature.Add(signature2);
            multiSignature.Add(signature3);

            ITlvTag[] tags = multiSignature.GetAllTags();

            Assert.AreEqual(5, tags.Count(t => t is AggregationHashChain), "Aggregation hash chain count does not match");
            Assert.AreEqual(1, multiSignature.GetUsedHashAlgorithms().Length, "Invalid used hash algorithm count.");
            Assert.AreEqual(1, tags.Count(t => t is CalendarHashChain), "Calendar hash chain count does not match");
            Assert.AreEqual(1, tags.Count(t => t is CalendarAuthenticationRecord), "Calendar authentication record count does not match");
            Assert.AreEqual(0, tags.Count(t => t is PublicationRecordInSignature), "Publication record count does not match");
            Assert.AreEqual(0, tags.Count(t => t is Rfc3161Record), "Rfc3161 record count does not match");
        }

        /// <summary>
        /// Test multi-signatures loading
        /// </summary>
        [Test]
        public void MultiSignatureLoadTest()
        {
            KsiMultiSignature multiSignature;

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.MultiSignature_Ok), FileMode.Open))
            {
                multiSignature = new KsiMultiSignature(stream, new KsiSignatureFactory());
            }

            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok);
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok_New);

            IKsiSignature outSig1 = multiSignature.Get(signature1.GetAggregationHashChains()[0].InputHash);
            IKsiSignature outSig2 = multiSignature.Get(signature2.GetAggregationHashChains()[0].InputHash);

            bool areEqual = AreEqual((KsiSignature)signature1, (KsiSignature)outSig1);
            if (!areEqual)
            {
                Console.WriteLine("Expected signature: " + signature1);
                Console.WriteLine("Signature out: " + outSig1);
                Assert.Fail("First signatures do not match");
            }

            areEqual = AreEqual((KsiSignature)signature2, (KsiSignature)outSig2);
            if (!areEqual)
            {
                Console.WriteLine("Expected signature: " + signature2);
                Console.WriteLine("Signature out: " + outSig2);
                Assert.Fail("Second signatures do not match");
            }
        }

        /// <summary>
        /// Test loading multi-signature containing 5 uni-signatures
        /// </summary>
        [Test]
        public void MultiSignatureLoadWith5UniSignaturesTest()
        {
            KsiMultiSignature multiSignature;

            // MultiSignatureWith5UniSignatures_Ok contains following uni-signatures
            //   KsiSignatureDo_Legacy_Ok
            //   KsiSignature_InputForMulti_sha2_384
            //   KsiSignatureDo_Ok_Extended
            //   KsiSignature_InputForMulti_sha2_512
            //   KsiSignature_InputForMulti_20150528_Ok

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.MultiSignatureWith5UniSignatures_Ok), FileMode.Open))
            {
                multiSignature = new KsiMultiSignature(stream, new KsiSignatureFactory());
            }

            ITlvTag[] tags = multiSignature.GetAllTags();

            Assert.IsTrue(tags.Count(t => t is AggregationHashChain) > 0, "Aggregation hash chain count should be greater than zero.");
            Assert.AreEqual(3, multiSignature.GetUsedHashAlgorithms().Length, "Invalid used hash algorithm count.");
            Assert.AreEqual(5, tags.Count(t => t is CalendarHashChain), "Calendar hash chain count does not match");
            Assert.AreEqual(4, tags.Count(t => t is CalendarAuthenticationRecord), "Calendar authentication record count does not match");
            Assert.AreEqual(1, tags.Count(t => t is PublicationRecordInSignature), "Publication record count does not match");
            Assert.AreEqual(1, tags.Count(t => t is Rfc3161Record), "RFC record count does not match");
        }

        /// <summary>
        /// Signature remove test
        /// </summary>
        [Test]
        public void MultiSignatureRemoveTest()
        {
            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok);
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok_New);

            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory());

            multiSignature.Add(signature1);
            multiSignature.Add(signature2);

            multiSignature.Remove(signature1.GetAggregationHashChains()[0].InputHash);

            Assert.Throws<KsiMultiSignatureInvalidHashException>(delegate
            {
                multiSignature.Get(signature1.GetAggregationHashChains()[0].InputHash);
            }, "First signature should be already removed");

            ITlvTag[] allTags = multiSignature.GetAllTags();
            Assert.AreEqual(((KsiSignature)signature2).Count, allTags.Length, "Tag count does not match.");

            bool areEqual = AreEqual((KsiSignature)signature2, allTags);
            if (!areEqual)
            {
                Console.WriteLine("Signature in: " + signature2);
                Console.WriteLine("Multi-signature tags: " + allTags);
                Assert.Fail("Only signature 2 tags should be left in multi-signature");
            }

            multiSignature.Remove(signature2.GetAggregationHashChains()[0].InputHash);
            Assert.AreEqual(0, multiSignature.GetAllTags().Length, "All tags should be removed from multi-signature.");
        }

        /// <summary>
        /// Signature remove not existing hash test
        /// </summary>
        [Test]
        public void MultiSignatureRemoveNotExistingTest()
        {
            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok);
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok_New);

            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory());

            multiSignature.Add(signature2);

            Assert.That(delegate
            {
                multiSignature.Remove(signature1.GetAggregationHashChains()[0].InputHash);
            }, Throws.TypeOf<KsiMultiSignatureInvalidHashException>());
        }

        /// <summary>
        /// Remove test with signatures having the same hash
        /// </summary>
        [Test]
        public void MultiSignatureRemoveWithSameHashTest()
        {
            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMulti_20150505_Ok);
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMulti_20150528_Ok);
            IKsiSignature signature3 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMulti_20150622_Ok);

            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory());

            multiSignature.Add(signature3);
            multiSignature.Add(signature1);
            multiSignature.Add(signature2);

            DataHash documentHash = signature1.GetAggregationHashChains()[0].InputHash;

            // the earliest signature should be returned by "get"
            Assert.AreEqual(1430850841, multiSignature.Get(documentHash).AggregationTime, "First signature get returned invalid signature");
            // the earliest signature should be removed
            multiSignature.Remove(documentHash);
            Assert.AreEqual(1432838040, multiSignature.Get(documentHash).AggregationTime, "Second signature get returned invalid signature");
            multiSignature.Remove(documentHash);
            Assert.AreEqual(1434998041, multiSignature.Get(documentHash).AggregationTime, "Thrid signature get returned invalid signature");
            multiSignature.Remove(documentHash);
            Assert.AreEqual(0, multiSignature.GetAllTags().Length, "All tags should be removed from multi-signature.");
        }

        /// <summary>
        /// Test removing legacy signature
        /// </summary>
        [Test]
        public void MultiSignatureRemoveLegacySignatureTest()
        {
            KsiMultiSignature multiSignature;

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.MultiSignatureWith5UniSignatures_Ok), FileMode.Open))
            {
                multiSignature = new KsiMultiSignature(stream, new KsiSignatureFactory());
            }

            multiSignature.Remove(GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Legacy_Ok).Rfc3161Record.InputHash);

            ITlvTag[] tags = multiSignature.GetAllTags();

            Assert.IsTrue(tags.Count(t => t is AggregationHashChain) > 0, "Aggregation hash chain count should be greater than zero.");

            Assert.AreEqual(3, multiSignature.GetUsedHashAlgorithms().Length, "Invalid used hash algorithm count.");
            Assert.AreEqual(4, tags.Count(t => t is CalendarHashChain), "Calendar hash chain count does not match");
            Assert.AreEqual(3, tags.Count(t => t is CalendarAuthenticationRecord), "Calendar authentication record count does not match");
            Assert.AreEqual(1, tags.Count(t => t is PublicationRecordInSignature), "Publication record count does not match");
            Assert.AreEqual(0, tags.Count(t => t is Rfc3161Record), "RFC record count does not match");
        }

        /// <summary>
        /// Test removing all legacy signatures
        /// </summary>
        [Test]
        public void MultiSignatureRemoveAllLegacySignaturesTest()
        {
            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMulti_Legacy_png_201504);
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMulti_Legacy_txt_201502);

            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory());

            multiSignature.Add(signature1);
            multiSignature.Add(signature2);

            ITlvTag[] tags = multiSignature.GetAllTags();

            Assert.AreEqual(1, multiSignature.GetUsedHashAlgorithms().Length, "Inital: Invalid used hash algorithm count.");
            Assert.AreEqual(2, tags.Count(t => t is CalendarHashChain), "Inital: Calendar hash chain count does not match");
            Assert.AreEqual(2, tags.Count(t => t is CalendarAuthenticationRecord), "Inital: Calendar authentication record count does not match");
            Assert.AreEqual(0, tags.Count(t => t is PublicationRecordInSignature), "Inital: Publication record count does not match");
            Assert.AreEqual(2, tags.Count(t => t is Rfc3161Record), "Inital: RFC record count does not match");

            IKsiSignature outSig1 = multiSignature.Get(signature1.Rfc3161Record.InputHash);
            Assert.AreEqual(1428181205, outSig1.AggregationTime, "First signature get returned invalid signature");
            Assert.IsNotNull(outSig1.Rfc3161Record, "First signature should contain a rfc3161 record. ");
            multiSignature.Remove(signature1.Rfc3161Record.InputHash);

            tags = multiSignature.GetAllTags();

            Assert.AreEqual(1, multiSignature.GetUsedHashAlgorithms().Length, "After first remove: Invalid used hash algorithm count.");
            Assert.AreEqual(1, tags.Count(t => t is CalendarHashChain), "After first remove: Calendar hash chain count does not match");
            Assert.AreEqual(1, tags.Count(t => t is CalendarAuthenticationRecord), "After first remove: Calendar authentication record count does not match");
            Assert.AreEqual(0, tags.Count(t => t is PublicationRecordInSignature), "After first remove: Publication record count does not match");
            Assert.AreEqual(1, tags.Count(t => t is Rfc3161Record), "After first remove: RFC record count does not match");

            IKsiSignature outSig2 = multiSignature.Get(signature2.Rfc3161Record.InputHash);
            Assert.AreEqual(1423087202, outSig2.AggregationTime, "Second signature get returned invalid signature");
            Assert.IsNotNull(outSig2.Rfc3161Record, "Second signature should contain a rfc3161 record. ");
            multiSignature.Remove(signature2.Rfc3161Record.InputHash);

            Assert.AreEqual(0, multiSignature.GetAllTags().Length, "All tags should be removed from multi-signature.");
        }

        /// <summary>
        /// Test removing all legacy signatures
        /// </summary>
        [Test]
        public void MultiSignatureRemoveAllSameHashLegacySignaturesTest()
        {
            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMulti_Legacy_txt_201505); // Aggregation time: 1430773202
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMulti_Legacy_txt_201502); // Aggregation time: 1423087202
            IKsiSignature signature3 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Legacy_Ok); // Aggregation time: 1401915603

            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory());

            multiSignature.Add(signature1);
            multiSignature.Add(signature2);
            multiSignature.Add(signature3);

            DataHash documentHash = signature1.Rfc3161Record.InputHash;

            ITlvTag[] tags = multiSignature.GetAllTags();

            Assert.AreEqual(1, multiSignature.GetUsedHashAlgorithms().Length, "Inital: Invalid used hash algorithm count.");
            Assert.AreEqual(3, tags.Count(t => t is CalendarHashChain), "Inital: Calendar hash chain count does not match");
            Assert.AreEqual(3, tags.Count(t => t is CalendarAuthenticationRecord), "Inital: Calendar authentication record count does not match");
            Assert.AreEqual(0, tags.Count(t => t is PublicationRecordInSignature), "Inital: Publication record count does not match");
            Assert.AreEqual(3, tags.Count(t => t is Rfc3161Record), "Inital: RFC record count does not match");

            IKsiSignature outSig1 = multiSignature.Get(signature1.Rfc3161Record.InputHash);
            // the earliest signature should be returned by "get"
            Assert.AreEqual(1401915603, outSig1.AggregationTime, "First signature get returned invalid signature");
            // the earliest signature should be removed
            Assert.IsNotNull(outSig1.Rfc3161Record, "First signature should contain a rfc3161 record. ");
            multiSignature.Remove(documentHash);

            tags = multiSignature.GetAllTags();

            Assert.AreEqual(1, multiSignature.GetUsedHashAlgorithms().Length, "After first remove: Invalid used hash algorithm count.");
            Assert.AreEqual(2, tags.Count(t => t is CalendarHashChain), "After first remove: Calendar hash chain count does not match");
            Assert.AreEqual(2, tags.Count(t => t is CalendarAuthenticationRecord), "After first remove: Calendar authentication record count does not match");
            Assert.AreEqual(0, tags.Count(t => t is PublicationRecordInSignature), "After first remove: Publication record count does not match");
            Assert.AreEqual(2, tags.Count(t => t is Rfc3161Record), "After first remove: RFC record count does not match");

            IKsiSignature outSig2 = multiSignature.Get(signature2.Rfc3161Record.InputHash);
            Assert.AreEqual(1423087202, outSig2.AggregationTime, "Second signature get returned invalid signature");
            Assert.IsNotNull(outSig2.Rfc3161Record, "Second signature should contain a rfc3161 record. ");
            multiSignature.Remove(documentHash);

            tags = multiSignature.GetAllTags();

            Assert.AreEqual(1, multiSignature.GetUsedHashAlgorithms().Length, "After second remove: Invalid used hash algorithm count.");
            Assert.AreEqual(1, tags.Count(t => t is CalendarHashChain), "After second remove: Calendar hash chain count does not match");
            Assert.AreEqual(1, tags.Count(t => t is CalendarAuthenticationRecord), "After second remove: Calendar authentication record count does not match");
            Assert.AreEqual(0, tags.Count(t => t is PublicationRecordInSignature), "After second remove: Publication record count does not match");
            Assert.AreEqual(1, tags.Count(t => t is Rfc3161Record), "After second remove: RFC record count does not match");

            IKsiSignature outSig3 = multiSignature.Get(signature3.Rfc3161Record.InputHash);
            Assert.AreEqual(1430773202, outSig3.AggregationTime, "Thrid signature get returned invalid signature");
            Assert.IsNotNull(outSig2.Rfc3161Record, "Third signature should contain a rfc3161 record. ");
            multiSignature.Remove(documentHash);
            Assert.AreEqual(0, multiSignature.GetAllTags().Length, "All tags should be removed from multi-signature.");
        }

        /// <summary>
        /// Remove signatures from the same aggregation round.
        /// </summary>
        [Test]
        public void MultiSignatureRemoveUniSignaturesFromSameAggregationRoundTest()
        {
            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory(), IntegrationTests.GetHttpKsiService());

            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMultiSameAggregationRound_1_Ok);
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMultiSameAggregationRound_2_Ok);
            IKsiSignature signature3 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMultiSameAggregationRound_3_Ok);

            multiSignature.Add(signature1);
            multiSignature.Add(signature2);
            multiSignature.Add(signature3);

            ITlvTag[] tags = multiSignature.GetAllTags();

            Assert.AreEqual(5, tags.Count(t => t is AggregationHashChain), "Initial: Aggregation hash chain count does not match");
            Assert.AreEqual(1, tags.Count(t => t is CalendarHashChain), "Initial: Calendar hash chain count does not match");
            Assert.AreEqual(1, tags.Count(t => t is CalendarAuthenticationRecord), "Initial: Calendar authentication record count does not match");
            Assert.AreEqual(0, tags.Count(t => t is PublicationRecordInSignature), "Initial: Publication record count does not match");

            multiSignature.Remove(signature1.GetAggregationHashChains()[0].InputHash);
            tags = multiSignature.GetAllTags();

            Assert.AreEqual(4, tags.Count(t => t is AggregationHashChain), "After first remove: Aggregation hash chain count does not match");
            Assert.AreEqual(1, tags.Count(t => t is CalendarHashChain), "After first remove: Calendar hash chain count does not match");
            Assert.AreEqual(1, tags.Count(t => t is CalendarAuthenticationRecord), "After first remove: Calendar authentication record count does not match");
            Assert.AreEqual(0, tags.Count(t => t is PublicationRecordInSignature), "After first remove: Publication record count does not match");

            multiSignature.Remove(signature2.GetAggregationHashChains()[0].InputHash);
            tags = multiSignature.GetAllTags();

            Assert.AreEqual(3, tags.Count(t => t is AggregationHashChain), "After second remove: Aggregation hash chain count does not match");
            Assert.AreEqual(1, tags.Count(t => t is CalendarHashChain), "After second remove: Calendar hash chain count does not match");
            Assert.AreEqual(1, tags.Count(t => t is CalendarAuthenticationRecord), "After second remove: Calendar authentication record count does not match");
            Assert.AreEqual(0, tags.Count(t => t is PublicationRecordInSignature), "After second remove: Publication record count does not match");

            multiSignature.Remove(signature3.GetAggregationHashChains()[0].InputHash);
            tags = multiSignature.GetAllTags();

            Assert.AreEqual(0, tags.Length, "All tags should be removed from multi-signature.");
        }

        /// <summary>
        /// Test extending all signatures to publication record. Re-extend extended signatures.
        /// </summary>
        [Test]
        public void MultiSignatureExtendAllWithPublicationRecordOverwriteTest()
        {
            MultiSignatureExtendAllWithPublicationRecordTest(true);
        }

        /// <summary>
        /// Test extending all signatures to publication record. Do not re-extend extended signatures.
        /// </summary>
        [Test]
        public void MultiSignatureExtendWAllithPublicationRecordNoOverwriteTest()
        {
            MultiSignatureExtendAllWithPublicationRecordTest(false);
        }

        /// <summary>
        /// Test extending all signatures to publication record. 
        /// </summary>
        public void MultiSignatureExtendAllWithPublicationRecordTest(bool overwrite)
        {
            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory(), IntegrationTests.GetHttpKsiService());

            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMultiSameAggregationRound_1_Ok); // created: 23.07.2015
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok_Extended); // created: 14.02.2016
            IKsiSignature signature3 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok_New); // created: 24.09.2015

            multiSignature.Add(signature1);
            multiSignature.Add(signature2);
            multiSignature.Add(signature3);

            ITlvTag[] tags = multiSignature.GetAllTags();

            PublicationRecordInSignature existingPublicationRecord = tags.OfType<PublicationRecordInSignature>().First();

            multiSignature.Extend(IntegrationTests.GetHttpKsiService().GetPublicationsFile().GetNearestPublicationRecord(new DateTime(2016, 3, 1)), overwrite);

            tags = multiSignature.GetAllTags();

            Assert.AreEqual(11, tags.Count(t => t is AggregationHashChain), "Aggregation hash chain count does not match");
            Assert.AreEqual(1, multiSignature.GetUsedHashAlgorithms().Length, "Invalid used hash algorithm count.");
            Assert.AreEqual(3, tags.Count(t => t is CalendarHashChain), "Calendar hash chain count does not match");
            Assert.AreEqual(0, tags.Count(t => t is CalendarAuthenticationRecord), "Calendar authentication record count does not match");

            if (overwrite)
            {
                Assert.AreEqual(1, tags.Count(t => t is PublicationRecordInSignature), "Publication record count does not match");
                Assert.IsTrue(tags.All(t => !ReferenceEquals(t, existingPublicationRecord)), "Publication record should be overwritten");
            }
            else
            {
                Assert.AreEqual(2, tags.Count(t => t is PublicationRecordInSignature), "Publication record count does not match");
                Assert.IsTrue(tags.Count(t => ReferenceEquals(t, existingPublicationRecord)) == 1, "Publication record should not be overwritten");
            }
        }

        /// <summary>
        /// Test extending one unextended signature. Re-extend already extended signature.
        /// </summary>
        [Test]
        public void MultiSignatureExtendOneWithPublicationRecordTestOverwriteTest()
        {
            MultiSignatureExtendOneWithPublicationRecordTest(true);
        }

        /// <summary>
        /// Test extending one unextended signature. Do not re-extend already extended signature.
        /// </summary>
        [Test]
        public void ExtendOneWithPublicationRecordTestNoOverwriteTest()
        {
            MultiSignatureExtendOneWithPublicationRecordTest(false);
        }

        /// <summary>
        /// Test extending one unextended signature. If "overwrite" is true then re-extend already extended signature.
        /// </summary>
        /// <param name="overwrite"></param>
        public void MultiSignatureExtendOneWithPublicationRecordTest(bool overwrite)
        {
            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory(), IntegrationTests.GetHttpKsiService());

            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMultiSameAggregationRound_1_Ok); // created: 23.07.2015
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok_Extended); // created: 14.02.2016
            IKsiSignature signature3 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok_New); // created: 24.09.2015

            multiSignature.Add(signature1);
            multiSignature.Add(signature2);
            multiSignature.Add(signature3);

            ITlvTag[] tags = multiSignature.GetAllTags();

            PublicationRecordInSignature existingPublicationRecord = tags.OfType<PublicationRecordInSignature>().First();

            multiSignature.Extend(IntegrationTests.GetHttpKsiService().GetPublicationsFile().GetNearestPublicationRecord(new DateTime(2015, 8, 1)), overwrite);

            tags = multiSignature.GetAllTags();

            Assert.AreEqual(11, tags.Count(t => t is AggregationHashChain), "Aggregation hash chain count does not match");
            Assert.AreEqual(1, multiSignature.GetUsedHashAlgorithms().Length, "Invalid used hash algorithm count.");
            Assert.AreEqual(3, tags.Count(t => t is CalendarHashChain), "Calendar hash chain count does not match");
            Assert.AreEqual(1, tags.Count(t => t is CalendarAuthenticationRecord), "Calendar authentication record count does not match");
            Assert.AreEqual(2, tags.Count(t => t is PublicationRecordInSignature), "Publication record count does not match");
            Assert.IsTrue(tags.Any(t => ReferenceEquals(t, existingPublicationRecord)), "Latest signature publication record should not be overwritten");
        }

        /// <summary>
        /// Test extending with publications file. Re-extend already extended signatures.
        /// </summary>
        [Test]
        public void MultiSignatureExtendWithPublicationsFileOverwriteTest()
        {
            MultiSignatureExtendWithPublicationsFileTest(true);
        }

        /// <summary>
        /// Test extending with publications file. Do not re-extend already extended signatures.
        /// </summary> 
        [Test]
        public void ExtendWithPublicationsFileNoOverwriteTest()
        {
            MultiSignatureExtendWithPublicationsFileTest(false);
        }

        /// <summary>
        /// Test extending with publications file
        /// </summary>
        /// <param name="overwrite"></param>
        public void MultiSignatureExtendWithPublicationsFileTest(bool overwrite)
        {
            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory(), IntegrationTests.GetHttpKsiService());

            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMultiSameAggregationRound_1_Ok); // created: 23.07.2015
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok_Extended); // created: 14.02.2016
            IKsiSignature signature3 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Ok_New); // created: 24.09.2015

            multiSignature.Add(signature1);
            multiSignature.Add(signature2);
            multiSignature.Add(signature3);

            ITlvTag[] tags = multiSignature.GetAllTags();

            PublicationRecordInSignature existingPublicationRecord = tags.OfType<PublicationRecordInSignature>().First();

            multiSignature.Extend(IntegrationTests.GetHttpKsiService().GetPublicationsFile(), overwrite);

            tags = multiSignature.GetAllTags();

            Assert.AreEqual(11, tags.Count(t => t is AggregationHashChain), "Aggregation hash chain count does not match");
            Assert.AreEqual(1, multiSignature.GetUsedHashAlgorithms().Length, "Invalid used hash algorithm count.");
            Assert.AreEqual(3, tags.Count(t => t is CalendarHashChain), "Calendar hash chain count does not match");
            Assert.AreEqual(0, tags.Count(t => t is CalendarAuthenticationRecord), "Calendar authentication record count does not match");
            Assert.AreEqual(3, tags.Count(t => t is PublicationRecordInSignature), "Publication record count does not match");

            if (overwrite)
            {
                Assert.IsTrue(tags.All(t => !ReferenceEquals(t, existingPublicationRecord)), "Publication record should be overwritten");
            }
            else
            {
                Assert.IsTrue(tags.Count(t => ReferenceEquals(t, existingPublicationRecord)) == 1, "Publication record should not be overwritten");
            }
        }

        /// <summary>
        /// Extend signatures from the same aggregation round.
        /// </summary>
        [Test]
        public void MultiSignatureExtendUniSignaturesFromSameAggregationRoundTest()
        {
            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory(), IntegrationTests.GetHttpKsiService());

            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMultiSameAggregationRound_1_Ok);
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMultiSameAggregationRound_2_Ok);
            IKsiSignature signature3 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMultiSameAggregationRound_3_Ok);

            multiSignature.Add(signature1);
            multiSignature.Add(signature2);
            multiSignature.Add(signature3);

            multiSignature.Extend(IntegrationTests.GetHttpKsiService().GetPublicationsFile());

            ITlvTag[] tags = multiSignature.GetAllTags();

            Assert.AreEqual(5, tags.Count(t => t is AggregationHashChain), "Aggregation hash chain count does not match");
            Assert.AreEqual(1, multiSignature.GetUsedHashAlgorithms().Length, "Invalid used hash algorithm count.");
            Assert.AreEqual(1, tags.Count(t => t is CalendarHashChain), "Calendar hash chain count does not match");
            Assert.AreEqual(0, tags.Count(t => t is CalendarAuthenticationRecord), "Calendar authentication record count does not match");
            Assert.AreEqual(1, tags.Count(t => t is PublicationRecordInSignature), "Publication record count does not match");
        }

        /// <summary>
        /// Test writing multi-signature
        /// </summary>
        [Test]
        public void MultiSignatureWriteTest()
        {
            KsiMultiSignature multiSignature;

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.MultiSignatureWith5UniSignatures_Ok), FileMode.Open))
            {
                multiSignature = new KsiMultiSignature(stream, new KsiSignatureFactory());
            }

            MemoryStream outStream = new MemoryStream();
            multiSignature.WriteTo(outStream);
            outStream.Seek(0, SeekOrigin.Begin);

            KsiMultiSignature newMultiSignature = new KsiMultiSignature(outStream, new KsiSignatureFactory());

            Assert.True(AreEqual(multiSignature.GetAllTags(), newMultiSignature.GetAllTags()), "Written multi-signature should match the inital signature.");
        }

        /// <summary>
        /// Test writing multi-signature
        /// </summary>
        [Test]
        public void MultiSignatureWriteWithMultipleRfc3161RecordsTest()
        {
            IKsiSignature signature1 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMulti_Legacy_txt_201505); // Aggregation time: 1430773202
            IKsiSignature signature2 = GetKsiSignatureFromFile(Properties.Resources.KsiSignature_InputForMulti_Legacy_txt_201502); // Aggregation time: 1423087202
            IKsiSignature signature3 = GetKsiSignatureFromFile(Properties.Resources.KsiSignatureDo_Legacy_Ok); // Aggregation time: 1401915603

            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory());

            multiSignature.Add(signature1);
            multiSignature.Add(signature2);
            multiSignature.Add(signature3);

            MemoryStream outStream = new MemoryStream();
            multiSignature.WriteTo(outStream);
            outStream.Seek(0, SeekOrigin.Begin);

            KsiMultiSignature newMultiSignature = new KsiMultiSignature(outStream, new KsiSignatureFactory());

            Assert.True(AreEqual(multiSignature.GetAllTags(), newMultiSignature.GetAllTags()), "Written multi-signature should match the inital signature.");
        }

        /// <summary>
        /// Get KsiSignature from file.
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        private static IKsiSignature GetKsiSignatureFromFile(string file)
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, file), FileMode.Open))
            {
                return new KsiSignatureFactory().Create(stream);
            }
        }

        /// <summary>
        /// Returns true if signatures are equal (have same content value)
        /// </summary>
        /// <param name="sig1"></param>
        /// <param name="sig2"></param>
        /// <returns></returns>
        private bool AreEqual(IEnumerable<ITlvTag> sig1, IEnumerable<ITlvTag> sig2)
        {
            IEnumerable<ITlvTag> tags1 = sig1 as ITlvTag[] ?? sig1.ToArray();
            IEnumerable<ITlvTag> tags2 = sig2 as ITlvTag[] ?? sig2.ToArray();

            List<TlvTag> diff1 = Diff(tags1, tags2);
            List<TlvTag> diff2 = Diff(tags2, tags1);

            foreach (TlvTag item in diff1)
            {
                Console.WriteLine("Tag in signature 1 and not in signature 2: " + item);
            }

            foreach (TlvTag item in diff1)
            {
                Console.WriteLine("Tag in signature 2 and not in signature 1: " + item);
            }

            return diff1.Count == 0 && diff2.Count == 0;
        }

        /// <summary>
        /// Returns list of tlv tags that exist in sig1, but do not exist in sig2
        /// </summary>
        /// <param name="sig1"></param>
        /// <param name="sig2"></param>
        /// <returns></returns>
        private List<TlvTag> Diff(IEnumerable<ITlvTag> sig1, IEnumerable<ITlvTag> sig2)
        {
            TlvTag[] tags1 = sig1.Cast<TlvTag>().ToArray();
            TlvTag[] tags2 = sig2.Cast<TlvTag>().ToArray();

            List<TlvTag> list = tags1.Where(tag => !tags2.Contains(tag)).ToList();
            list.AddRange(tags2.Where(tag => !tags1.Contains(tag)));

            return list;
        }
    }
}