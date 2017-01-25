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
using System.Text;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Utils
{
    /// <summary>
    ///     Utilities object.
    /// </summary>
    public static class Util
    {
        private static readonly Random Random = new Random();

        /// <summary>
        ///     Clone given byte array
        /// </summary>
        /// <param name="source">byte array to be cloned</param>
        /// <returns></returns>
        public static byte[] Clone(byte[] source)
        {
            byte[] bytes = new byte[source.Length];
            source.CopyTo(bytes, 0);
            return bytes;
        }

        /// <summary>
        ///     Clone part of byte array
        /// </summary>
        /// <param name="source">byte array to be cloned</param>
        /// <param name="startIndex">source array index to start cloning from</param>
        /// <param name="byteCount">amount of bytes to clone</param>
        /// <returns></returns>
        public static byte[] Clone(byte[] source, int startIndex, int byteCount)
        {
            byte[] bytes = new byte[byteCount];
            Array.Copy(source, startIndex, bytes, 0, byteCount);
            return bytes;
        }

        /// <summary>
        ///     Are given arrays equal with same data ordering.
        /// </summary>
        /// <typeparam name="T">any type</typeparam>
        /// <param name="arr1">first array</param>
        /// <param name="arr2">second array</param>
        /// <returns>true if arrays are equal</returns>
        public static bool IsArrayEqual<T>(T[] arr1, T[] arr2)
        {
            if (arr1 == null || arr2 == null)
            {
                return arr1 == arr2;
            }

            if (arr1.Length != arr2.Length)
            {
                return false;
            }

            for (int i = 0; i < arr1.Length; i++)
            {
                if (!Equals(arr1[i], arr2[i]))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Are parts of given arrays equal
        /// </summary>
        /// <param name="arr1">first array</param>
        /// <param name="arr2">second array</param>
        /// <param name="index">index where to start comparing items</param>
        /// <param name="count">item count to compare</param>
        /// <typeparam name="T">any type</typeparam>
        /// <returns></returns>
        public static bool IsArrayEqual<T>(T[] arr1, T[] arr2, int index, int count)
        {
            for (int i = index; i < index + count; i++)
            {
                if (!Equals(arr1[i], arr2[i]))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Returns array elements as a string (elements are separated by comma).
        /// </summary>
        /// <param name="arr">Array</param>
        /// <returns></returns>
        public static string ArrayToString<T>(T[] arr)
        {
            string result = "";

            for (int i = 0; i < arr.Length; i++)
            {
                if (i > 0)
                {
                    result += ", ";
                }

                result += arr[i];
            }

            return result;
        }

        /// <summary>
        ///     Decode byte array to unsigned long.
        /// </summary>
        /// <param name="buf">byte array</param>
        /// <param name="ofs">data offset</param>
        /// <param name="len">data length</param>
        /// <returns>unsigned long</returns>
        public static ulong DecodeUnsignedLong(byte[] buf, int ofs, int len)
        {
            if (buf == null)
            {
                throw new KsiException("Input byte array cannot be null.");
            }

            if (ofs < 0 || len < 0 || ofs + len < 0 || ofs + len > buf.Length)
            {
                throw new KsiException("Index out of bounds.");
            }
            if (len > 8)
            {
                throw new KsiException("Integers of at most 63 unsigned bits supported by this implementation.");
            }

            ulong t = 0;
            for (int i = 0; i < len; ++i)
            {
                t = (t << 8) | buf[ofs + i];
            }

            return t;
        }

        /// <summary>
        ///     Encode unsigned long to byte array.
        /// </summary>
        /// <param name="value">unsigned long</param>
        /// <returns>byte array</returns>
        public static byte[] EncodeUnsignedLong(ulong value)
        {
            int n = 0;

            for (ulong t = value; t > 0; t >>= 8)
            {
                ++n;
            }

            byte[] res = new byte[n];

            for (ulong t = value; t > 0; t >>= 8)
            {
                res[--n] = (byte)t;
            }

            return res;
        }

        /// <summary>
        ///     Convert DateTime to unix time.
        /// </summary>
        /// <param name="time">time in DateTime format</param>
        /// <returns>unix time</returns>
        public static ulong ConvertDateTimeToUnixTime(DateTime time)
        {
            TimeSpan timeSpan = time - new DateTime(1970, 1, 1, 0, 0, 0);
            return (ulong)timeSpan.TotalSeconds;
        }

        /// <summary>
        ///     Convert unix time to DateTime.
        /// </summary>
        /// <param name="time">unix time</param>
        /// <returns>time as DateTime</returns>
        public static DateTime ConvertUnixTimeToDateTime(ulong time)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0) + TimeSpan.FromSeconds(time);
        }

        /// <summary>
        ///     Decode null terminated UTF-8 string from bytes.
        /// </summary>
        /// <param name="bytes">string bytes</param>
        /// <returns>utf-8 string</returns>
        public static string DecodeNullTerminatedUtf8String(byte[] bytes)
        {
            if (bytes == null)
            {
                throw new KsiException("Input bytes cannot be null.");
            }

            if (bytes.Length == 0 || bytes[bytes.Length - 1] != 0)
            {
                throw new KsiException("String must be null terminated.");
            }

            return Encoding.UTF8.GetString(bytes, 0, bytes.Length - 1);
        }

        /// <summary>
        ///     Encode null terminated byte array to UTF-8 string.
        /// </summary>
        /// <param name="value">utf-8 string</param>
        /// <returns>byte array</returns>
        public static byte[] EncodeNullTerminatedUtf8String(string value)
        {
            if (value == null)
            {
                throw new KsiException("Input string cannot be null.");
            }

            byte[] stringBytes = Encoding.UTF8.GetBytes(value);
            byte[] bytes = new byte[stringBytes.Length + 1];
            Array.Copy(stringBytes, 0, bytes, 0, stringBytes.Length);
            return bytes;
        }

        /// <summary>
        ///     Get random unsigned long.
        /// </summary>
        /// <returns>random unsigned long</returns>
        public static ulong GetRandomUnsignedLong()
        {
            byte[] bytes = new byte[8];
            Random.NextBytes(bytes);
            return BitConverter.ToUInt64(bytes, 0);
        }

        /// <summary>
        ///     Fill array with specific value
        /// </summary>
        /// <param name="arr">array of values</param>
        /// <param name="value">value to write to array</param>
        /// <typeparam name="T">array type</typeparam>
        public static void ArrayFill<T>(T[] arr, T value)
        {
            if (arr == null)
            {
                throw new KsiException("Input array cannot be null.");
            }

            for (int i = 0; i < arr.Length; i++)
            {
                arr[i] = value;
            }
        }

        /// <summary>
        ///     Find the Greatest Common Divisor
        /// </summary>
        /// <param name="a">Number a</param>
        /// <param name="b">Number b</param>
        /// <returns>The greatest common Divisor</returns>
        public static int GetGreatestCommonDivisor(int a, int b)
        {
            while (b != 0)
            {
                int tmp = b;
                b = a % b;
                a = tmp;
            }

            return a;
        }

        /// <summary>
        ///     Find the Least Common Multiple
        /// </summary>
        /// <param name="a">Number a</param>
        /// <param name="b">Number b</param>
        /// <returns>The least common multiple</returns>
        public static int GetLeastCommonMultiple(int a, int b)
        {
            return a * b / GetGreatestCommonDivisor(a, b);
        }

        /// <summary>
        ///     Put tab prefix instead of new rows.
        /// </summary>
        /// <param name="s">string</param>
        /// <returns>tab prefixed string</returns>
        public static string TabPrefixString(string s)
        {
            StringBuilder builder = new StringBuilder();

            string[] lines = s.Split(new[] { Environment.NewLine }, StringSplitOptions.None);

            for (int i = 0; i < lines.Length; i++)
            {
                builder.Append("  ");
                builder.Append(lines[i]);
                if (i != lines.Length - 1)
                {
                    builder.AppendLine();
                }
            }

            return builder.ToString();
        }

        /// <summary>
        /// Checks is exactly one value is equal to given/expected value.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="expectedValue">value to compare against</param>
        /// <param name="values"></param>
        /// <returns></returns>
        public static bool IsOneValueEqualTo<T>(T expectedValue, params T[] values)
        {
            int count = 0;
            foreach (T value in values)
            {
                if (expectedValue == null)
                {
                    if (value != null)
                    {
                        continue;
                    }
                }
                else if (!expectedValue.Equals(value))
                {
                    continue;
                }

                count++;

                if (count > 1)
                {
                    return false;
                }
            }

            return count == 1;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="headerBytes"></param>
        /// <returns></returns>
        public static ushort GetTlvLength(byte[] headerBytes)
        {
            if (headerBytes == null)
            {
                throw new KsiException("Input array cannot be null.");
            }

            if (headerBytes.Length == 0)
            {
                throw new KsiException("Input array cannot be empty.");
            }

            bool tlv16 = (headerBytes[0] & Constants.Tlv.Tlv16Flag) != 0;

            if (tlv16)
            {
                if (headerBytes.Length < 4)
                {
                    throw new KsiException("It is 16-bit TLV and input array must contain at least 4 bytes. headerBytes.Length: " + headerBytes.Length);
                }

                int variableLength = (headerBytes[2] << Constants.BitsInByte) | headerBytes[3];

                // first 2 bytes + 2 length bytes + data bytes
                return (ushort)(4 + variableLength);
            }

            if (headerBytes.Length < 2)
            {
                throw new KsiException("It is 8-bit TLV and input array must contain at least 2 bytes. headerBytes.Length: " + headerBytes.Length);
            }

            // first byte + length byte + data bytes
            return (ushort)(2 + headerBytes[1]);
        }

        /// <summary>
        ///     Write TLV object to given stream.
        /// </summary>
        /// <param name="tag">TLV object</param>
        public static ushort GetTlvLength(ITlvTag tag)
        {
            if (tag == null)
            {
                throw new ArgumentNullException(nameof(tag));
            }

            byte[] data = tag.EncodeValue();
            bool tlv16 = tag.Type > Constants.Tlv.TypeMask
                         || (data != null && data.Length > byte.MaxValue);

            if (tlv16)
            {
                if (data != null && data.Length > ushort.MaxValue)
                {
                    throw new ArgumentOutOfRangeException(nameof(data));
                }

                // first 2 bytes + 2 length bytes + data
                return (ushort)(4 + (data?.Length ?? 0));
            }

            // first byte + length byte + data
            return (ushort)(2 + (data?.Length ?? 0));
        }
    }
}