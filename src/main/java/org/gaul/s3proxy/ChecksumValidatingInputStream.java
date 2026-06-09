/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gaul.s3proxy;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Base64;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hasher;

/**
 * Validates a request body against a precomputed flexible-checksum header
 * (e.g. {@code x-amz-checksum-sha256}) supplied with a PutObject request.
 *
 * <p>The checksum is computed as the body streams through to the backend.
 * Validation fires as soon as the declared content length has been read (or
 * the stream reaches EOF, whichever comes first); the backend typically reads
 * exactly content-length bytes and never advances to EOF, so relying on EOF
 * alone would skip validation.  On mismatch an {@link S3Exception} carrying
 * {@link S3ErrorCode#BAD_DIGEST} is thrown (wrapped in an {@link IOException},
 * which {@code S3ProxyHandlerJetty} unwraps).  This matches the response real
 * Amazon S3 returns &mdash; HTTP 400 {@code BadDigest} with a message such as
 * "The SHA256 you specified did not match the calculated checksum." &mdash;
 * and mirrors the trailer validation in {@link ChunkedInputStream}.  Because
 * the throw happens while the body is being read, the backend never commits
 * the blob.
 */
final class ChecksumValidatingInputStream extends FilterInputStream {
    private final Hasher hasher;
    private final boolean bigEndianInt;
    private final String algorithm;
    private final String expected;
    private final long contentLength;
    private long read;
    private boolean validated;

    /**
     * @param in            the body stream to validate
     * @param function      the checksum algorithm
     * @param bigEndianInt  true for CRC checksums, whose 4-byte big-endian
     *                      representation is base64-encoded by AWS; false for
     *                      SHA checksums, which encode the raw digest bytes
     * @param algorithm     the algorithm label used in the error message
     *                      (e.g. "SHA256")
     * @param expected      the base64-encoded checksum supplied by the client
     * @param contentLength the declared object length, in bytes
     */
    ChecksumValidatingInputStream(InputStream in, HashFunction function,
            boolean bigEndianInt, String algorithm, String expected,
            long contentLength) {
        super(in);
        this.hasher = function.newHasher();
        this.bigEndianInt = bigEndianInt;
        this.algorithm = algorithm;
        this.expected = expected;
        this.contentLength = contentLength;
    }

    @Override
    public int read() throws IOException {
        int value = in.read();
        if (value == -1) {
            validate();
        } else {
            hasher.putByte((byte) value);
            if (++read >= contentLength) {
                validate();
            }
        }
        return value;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int count = in.read(b, off, len);
        if (count == -1) {
            validate();
        } else {
            hasher.putBytes(b, off, count);
            read += count;
            if (read >= contentLength) {
                validate();
            }
        }
        return count;
    }

    private void validate() throws IOException {
        if (validated) {
            return;
        }
        validated = true;
        // CRC checksums are base64-encoded from their big-endian 4-byte
        // representation; SHA checksums encode the raw digest bytes.
        byte[] actual = bigEndianInt ?
                ByteBuffer.allocate(4).putInt(hasher.hash().asInt()).array() :
                hasher.hash().asBytes();
        if (!expected.equals(Base64.getEncoder().encodeToString(actual))) {
            throw new IOException(new S3Exception(S3ErrorCode.BAD_DIGEST,
                    "The " + algorithm + " you specified did not match the " +
                    "calculated checksum."));
        }
    }
}
