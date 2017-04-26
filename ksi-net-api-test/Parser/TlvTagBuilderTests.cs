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
using Guardtime.KSI.Parser;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Parser
{
    [TestFixture]
    public class TlvTagBuilderTests
    {
        [Test]
        public void TlvTagBuilderCreateNullTest()
        {
            Assert.Throws<ArgumentNullException>(delegate
            {
                TlvTagBuilder builder = new TlvTagBuilder(null);
            });
        }

        [Test]
        public void TlvTagBuilderAddNullTest()
        {
            RawTag child1 = new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 });

            CompositeTestTag tag = new CompositeTestTag(0x1, false, false,
                new ITlvTag[]
                {
                    child1
                });

            TlvTagBuilder builder = new TlvTagBuilder(tag);

            Assert.Throws<ArgumentNullException>(delegate
            {
                builder.AddChildTag(null);
            });
        }

        [Test]
        public void TlvTagBuilderAddTest()
        {
            RawTag child1 = new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 });
            RawTag child2 = new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 });

            CompositeTestTag tag = new CompositeTestTag(0x1, false, false,
                new ITlvTag[]
                {
                    child1
                });

            TlvTagBuilder builder = new TlvTagBuilder(tag);

            builder.AddChildTag(child2);

            CompositeTestTag newTag = new CompositeTestTag(builder.BuildTag());

            CollectionAssert.AreEqual(newTag[1].EncodeValue(), child2.EncodeValue(), "Invalid second child.");
        }

        [Test]
        public void TlvTagBuilderRemoveNullTest()
        {
            RawTag child1 = new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 });

            CompositeTestTag tag = new CompositeTestTag(0x1, false, false,
                new ITlvTag[]
                {
                    child1
                });

            TlvTagBuilder builder = new TlvTagBuilder(tag);

            Assert.Throws<ArgumentNullException>(delegate
            {
                builder.RemoveChildTag(null);
            });
        }

        [Test]
        public void TlvTagBuilderRemoveTest()
        {
            RawTag child1 = new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 });
            RawTag child2 = new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 });

            CompositeTestTag tag = new CompositeTestTag(0x1, false, false,
                new ITlvTag[]
                {
                    child1,
                    child2
                });

            TlvTagBuilder builder = new TlvTagBuilder(tag);

            builder.RemoveChildTag(child1);

            CompositeTestTag newTag = new CompositeTestTag(builder.BuildTag());

            Assert.AreEqual(1, newTag.Count, "Invalid child tag count.");
            CollectionAssert.AreEqual(newTag[0].EncodeValue(), child2.EncodeValue(), "Invalid first child.");
        }

        [Test]
        public void TlvTagBuilderReplaceNull1Test()
        {
            RawTag child1 = new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 });

            CompositeTestTag tag = new CompositeTestTag(0x1, false, false,
                new ITlvTag[]
                {
                    child1
                });

            TlvTagBuilder builder = new TlvTagBuilder(tag);

            Assert.Throws<ArgumentNullException>(delegate
            {
                builder.ReplaceChildTag(null, child1);
            });
        }

        [Test]
        public void TlvTagBuilderReplaceNull2Test()
        {
            RawTag child1 = new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 });

            CompositeTestTag tag = new CompositeTestTag(0x1, false, false,
                new ITlvTag[]
                {
                    child1
                });

            TlvTagBuilder builder = new TlvTagBuilder(tag);

            Assert.Throws<ArgumentNullException>(delegate
            {
                builder.ReplaceChildTag(child1, null);
            });
        }

        [Test]
        public void TlvTagBuilderReplaceTest()
        {
            RawTag child1 = new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 });
            RawTag child2 = new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 });
            RawTag child3 = new RawTag(0x3, true, false, new byte[] { 0x5 });

            CompositeTestTag tag = new CompositeTestTag(0x1, false, false,
                new ITlvTag[]
                {
                    child1,
                    child2
                });

            TlvTagBuilder builder = new TlvTagBuilder(tag);

            builder.ReplaceChildTag(child1, child3);

            CompositeTestTag newTag = new CompositeTestTag(builder.BuildTag());

            Assert.AreEqual(2, newTag.Count, "Invalid child tag count.");
            CollectionAssert.AreEqual(newTag[0].EncodeValue(), child3.EncodeValue(), "Invalid first child.");
            CollectionAssert.AreEqual(newTag[1].EncodeValue(), child2.EncodeValue(), "Invalid second child.");
        }

        [Test]
        public void TlvTagBuilderGetTagByTypeTest()
        {
            RawTag child1 = new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 });
            RawTag child2 = new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 });

            CompositeTestTag tag = new CompositeTestTag(0x1, false, false,
                new ITlvTag[]
                {
                    child1,
                    child2
                });

            TlvTagBuilder builder = new TlvTagBuilder(tag);

            ITlvTag seachedTag = builder.GetChildByType(0x2);
            CollectionAssert.AreEqual(seachedTag.EncodeValue(), child2.EncodeValue(), "Invalid child returned.");
        }

        [Test]
        public void TlvTagBuilderGetTagByTypeReturnNullTest()
        {
            RawTag child1 = new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 });

            CompositeTestTag tag = new CompositeTestTag(0x1, false, false,
                new ITlvTag[]
                {
                    child1,
                });

            TlvTagBuilder builder = new TlvTagBuilder(tag);

            ITlvTag searchedTag = builder.GetChildByType(0x2);
            Assert.IsNull(searchedTag, "Invalid return tag");
        }
    }
}