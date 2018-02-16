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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Publication
{
    [TestFixture]
    public class PublicationsFileHeaderTests
    {
        [Test]
        public void PublicationsFileHeaderTest()
        {
            PublicationsFileHeader tag = new PublicationsFileHeader(new TlvTagBuilder(Constants.PublicationsFileHeader.TagType, false, false,
                new ITlvTag[]
                {
                    new IntegerTag(Constants.PublicationsFileHeader.VersionTagType, false, false, 1),
                    new IntegerTag(Constants.PublicationsFileHeader.CreationTimeTagType, false, false, 2),
                    new StringTag(Constants.PublicationsFileHeader.RepositoryUriTagType, false, false, "Test repository uri"),
                }).BuildTag());

            Assert.AreEqual(1, tag.Version, "Unexpected version value");
            Assert.AreEqual(2, tag.CreationTime, "Unexpected creation time");
            Assert.AreEqual("Test repository uri", tag.RepositoryUri, "Unexpected repository uri");
        }

        [Test]
        public void PublicationsFileHeaderWithoutVersionTest()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new PublicationsFileHeader(new TlvTagBuilder(Constants.PublicationsFileHeader.TagType, false, false,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.PublicationsFileHeader.CreationTimeTagType, false, false, 2),
                        new StringTag(Constants.PublicationsFileHeader.RepositoryUriTagType, false, false, "Test repository uri"),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Exactly one version must exist in publications file header."));
        }

        [Test]
        public void PublicationsFileHeaderWithoutCreationTimeTest()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new PublicationsFileHeader(new TlvTagBuilder(Constants.PublicationsFileHeader.TagType, false, false,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.PublicationsFileHeader.VersionTagType, false, false, 1),
                        new StringTag(Constants.PublicationsFileHeader.RepositoryUriTagType, false, false, "Test repository uri"),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Exactly one creation time must exist in publications file header."));
        }

        [Test]
        public void PublicationsFileHeaderWithMultipleRepositoryUrisTest()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new PublicationsFileHeader(new TlvTagBuilder(Constants.PublicationsFileHeader.TagType, false, false,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.PublicationsFileHeader.VersionTagType, false, false, 1),
                        new IntegerTag(Constants.PublicationsFileHeader.CreationTimeTagType, false, false, 2),
                        new StringTag(Constants.PublicationsFileHeader.RepositoryUriTagType, false, false, "Test repository uri 1"),
                        new StringTag(Constants.PublicationsFileHeader.RepositoryUriTagType, false, false, "Test repository uri 2"),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Only one repository uri is allowed in publications file header."));
        }

        [Test]
        public void ToStringTest()
        {
            PublicationsFileHeader tag =
                TestUtil.GetCompositeTag<PublicationsFileHeader>(Constants.PublicationsFileHeader.TagType,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.PublicationsFileHeader.VersionTagType, false, false, 1),
                        new IntegerTag(Constants.PublicationsFileHeader.CreationTimeTagType, false, false, 2),
                        new StringTag(Constants.PublicationsFileHeader.RepositoryUriTagType, false, false, "Test repository uri"),
                    });

            PublicationsFileHeader tag2 = new PublicationsFileHeader(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }
    }
}