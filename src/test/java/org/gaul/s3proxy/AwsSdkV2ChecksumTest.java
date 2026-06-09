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

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.Base64;

import com.google.common.hash.Hashing;

import org.assertj.core.api.Fail;
import org.jclouds.blobstore.BlobStoreContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * Tests PutObject flexible-checksum validation using the AWS SDK v2.  The
 * existing {@link AwsSdkTest} is written against the v1 SDK, which has no API
 * for supplying a precomputed flexible checksum, so these cases live in a
 * separate v2 class.  Uses the plaintext endpoint to avoid configuring the
 * (runtime-scoped) v2 HTTP client for the self-signed TLS endpoint.
 */
public final class AwsSdkV2ChecksumTest {
    private S3Proxy s3Proxy;
    private BlobStoreContext context;
    private S3Client client;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        var info = TestUtils.startS3Proxy(
                System.getProperty("s3proxy.test.conf", "s3proxy.conf"));
        s3Proxy = info.getS3Proxy();
        context = info.getBlobStore().getContext();
        var creds = AwsBasicCredentials.create(info.getS3Identity(),
                info.getS3Credential());
        var endpoint = URI.create(
                info.getEndpoint().toString() + info.getServicePath());
        client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(creds))
                .region(Region.US_EAST_1)
                .endpointOverride(endpoint)
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build();
        containerName = TestUtils.createRandomContainerName();
        info.getBlobStore().createContainerInLocation(null, containerName);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (client != null) {
            client.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (context != null) {
            context.getBlobStore().deleteContainer(containerName);
            context.close();
        }
    }

    @Test
    public void testPutObjectWithCorrectChecksumSha256() throws Exception {
        var key = "correct-checksum";
        byte[] data = TestUtils.randomByteSource().slice(0, 1024).read();
        String checksum = Base64.getEncoder().encodeToString(
                Hashing.sha256().hashBytes(data).asBytes());

        // A precomputed checksum matching the body is accepted.
        client.putObject(b -> b.bucket(containerName).key(key)
                        .checksumSHA256(checksum),
                RequestBody.fromBytes(data));

        // The object was stored.
        client.headObject(b -> b.bucket(containerName).key(key));
    }

    @Test
    public void testPutObjectWithMismatchedChecksumSha256() throws Exception {
        var key = "mismatched-checksum";
        byte[] data = TestUtils.randomByteSource().slice(0, 1024).read();
        // A valid-length SHA256 (base64 of 32 zero bytes) that does not match
        // the body.  Real S3 rejects this with HTTP 400 BadDigest; the proxy
        // must do the same so callers can exercise their error handling.
        String wrongChecksum = Base64.getEncoder().encodeToString(
                new byte[32]);

        try {
            client.putObject(b -> b.bucket(containerName).key(key)
                            .checksumSHA256(wrongChecksum),
                    RequestBody.fromBytes(data));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(400);
            assertThat(e.awsErrorDetails().errorCode()).isEqualTo("BadDigest");
        }

        // The rejected object must not have been stored.
        try {
            client.headObject(b -> b.bucket(containerName).key(key));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(404);
        }
    }
}
