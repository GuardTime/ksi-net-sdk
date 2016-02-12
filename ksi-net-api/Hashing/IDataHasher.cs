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

namespace Guardtime.KSI.Hashing
{
    /// <summary>
    /// Data hasher
    /// </summary>
    public interface IDataHasher
    {
        /// <summary>
        ///     Updates the digest using the specified array of bytes, starting at the specified offset.
        /// </summary>
        /// <param name="data">the list of bytes.</param>
        /// <param name="offset">the offset to start from in the array of bytes.</param>
        /// <param name="length">the number of bytes to use, starting at the offset.</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        IDataHasher AddData(byte[] data, int offset, int length);

        /// <summary>
        ///     Adds data to the digest using the specified array of bytes, starting at an offset of 0.
        /// </summary>
        /// <param name="data">list of bytes</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        IDataHasher AddData(byte[] data);

        /// <summary>
        ///     Adds data to the digest using the specified input stream of bytes, starting at an offset of 0.
        /// </summary>
        /// <param name="inStream">input stream of bytes.</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        IDataHasher AddData(Stream inStream);

        /// <summary>
        ///     Adds data to the digest using the specified input stream of bytes, starting at an offset of 0.
        /// </summary>
        /// <param name="inStream">input stream of bytes.</param>
        /// <param name="bufferSize">maximum allowed buffer size for reading data</param>
        /// <returns>the same DataHasher object for chaining calls</returns>
        IDataHasher AddData(Stream inStream, int bufferSize);

        /// <summary>
        ///     Get the final hash value for the digest.
        ///     This will not reset hash calculation.
        /// </summary>
        /// <returns>calculated hash</returns>
        DataHash GetHash();

        /// <summary>
        ///     Resets hash calculation.
        /// </summary>
        /// <returns>the same DataHasher object for chaining calls</returns>
        IDataHasher Reset();
    }
}