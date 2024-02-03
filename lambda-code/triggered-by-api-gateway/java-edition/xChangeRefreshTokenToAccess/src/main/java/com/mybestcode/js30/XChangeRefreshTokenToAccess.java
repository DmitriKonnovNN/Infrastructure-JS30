package com.mybestcode.js30;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import software.amazon.awssdk.services.ssm.model.Parameter;


import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serial;
import java.io.Serializable;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public class XChangeRefreshTokenToAccess implements RequestHandler <XChangeRefreshTokenToAccess.InputObject, String> {
    private static final String CIPHER_KEY_FULLNAME = "/sandbox/metax7/js30/dev/JS30_REFRESH_TOKEN_CIPHER_KEY";
    private static final boolean WITH_DECRYPTION = true;
    private static final String AWS_SESSION_TOKEN = System.getenv("AWS_SESSION_TOKEN");
    private static final String ENCODING_SCHEME = "base64";
    private static final int IV_BASE64_SIZE = 24;
    private static final int KEY_VERSION_BASE64_SIZE = 4;
    private static final String ENCRYPTION_ALG = "AES/CBC/PKCS5Padding";
    private static final String GOOGLE_URL = "https://oauth2.googleapis.com/token";
    private static final String SSM_URL = "http://localhost:2773/systemsmanager/parameters/get";
    private static final String REVOKED_KEY_VERSIONS = System.getenv("REVOKED_KEY_VERSIONS");

    @Override
    public String handleRequest(XChangeRefreshTokenToAccess.InputObject input, Context context) {
        if (input.idpRefreshToken() == null){
            System.out.println("No idp refresh token passed.");
            throw new NullPointerException("No idp refresh token passed.");
        }
        final DecodedData decodedData = Optional.ofNullable(
                decodeData(input.idpRefreshToken()))
                .orElseThrow(()-> new RuntimeException(String.format("Decoding of data failed. Is it %s encoded?", ENCODING_SCHEME )));

        CompletableFuture<Parameter> cipherKey = retrieveSecuredParameter(CIPHER_KEY_FULLNAME + ":" + decodedData.keyVersion());
        CompletableFuture<Parameter> clientId =  retrieveSecuredParameter("/sandbox/metax7/js30/dev/JS30_GOOGLE_CLIENT_ID");
        CompletableFuture<Parameter> clientSecret = retrieveSecuredParameter("/sandbox/metax7/js30/dev/JS30_GOOGLE_CLIENT_SECRET");

        String plaintext = decrypt(decodedData.ciphertext(), cipherKey.join().value(), decodedData.iv());

        GoogleTokenResponse freshData = refreshTokens(clientId.join().value(), clientSecret.join().value(), plaintext).join();

        // Output result
        System.out.println("Encrypted with key version: " + decodedData.keyVersion());
        System.out.println("Access Token: " + freshData.accessToken());

        return freshData.accessToken();
    }

    private static DecodedData decodeData(String encodedCiphertext) {
        try {
            // Extract key version, IV, and encrypted text from the input
            String keyVersionEncoded = encodedCiphertext.substring(0, KEY_VERSION_BASE64_SIZE);
            int keyVersion = Integer.parseInt(new String(Base64.getDecoder().decode(keyVersionEncoded)));

            if (keyVersion < 1 || keyVersion > 100) {
                throw new RuntimeException("Invalid key version: " + keyVersion + ". Allowed SSM parameter versions: 1-100");
            }

            if (REVOKED_KEY_VERSIONS.contains(String.valueOf(keyVersion))) {
                throw new RuntimeException("Invalid key version: " + keyVersion + ". This cipherkey is revoked.");
            }

            String ivBase64 = encodedCiphertext.substring(KEY_VERSION_BASE64_SIZE, KEY_VERSION_BASE64_SIZE + IV_BASE64_SIZE);
            byte[] iv = Base64.getDecoder().decode(ivBase64);
            String ciphertext = encodedCiphertext.substring(KEY_VERSION_BASE64_SIZE + IV_BASE64_SIZE);

            return new DecodedData(keyVersion, iv, Base64.getDecoder().decode(ciphertext));
        } catch (Exception e) {
            handleGenericError(e);
            return null;
        }
    }
    private static String decrypt(byte[] ciphertext, String cipherkey, byte[] iv) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(cipherkey), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALG);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decrypted = cipher.doFinal(ciphertext);
            return new String(decrypted, ENCODING_SCHEME);
        } catch (Exception e) {
            handleGenericError(e);
            return null; // Handle this properly based on your requirements
        }
    }

    private static CompletableFuture<GoogleTokenResponse> refreshTokens(String clientId, String clientSecret, String refreshToken) {
        HttpClient httpClient = HttpClient.newHttpClient();

        HttpRequest.BodyPublisher body = HttpRequest.BodyPublishers.ofString(
                "grant_type=refresh_token&client_id=" + clientId + "&refresh_token=" + refreshToken + "&clientSecret=" + clientSecret);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(GOOGLE_URL))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(body)
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString()).thenApply(response -> {
            Gson gson = new Gson();
            return gson.fromJson(response.body(), GoogleTokenResponse.class);
        });
    }

    private static CompletableFuture<Parameter> retrieveSecuredParameter(String queryParameter) {
        HttpClient httpClient = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(SSM_URL + "?name=" + queryParameter + "&withDecryption=" + WITH_DECRYPTION))
                .header("X-Aws-Parameters-Secrets-Token", AWS_SESSION_TOKEN)
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> {
                    Gson gson = new Gson();
                    return gson.fromJson(response.body(), Parameter.class);
                });
    }

    private record DecodedData(
            int keyVersion,
            byte[] iv,
            byte[] ciphertext) implements Serializable {}


    private static RuntimeException handleGenericError(Throwable error) {
        System.err.println("Unexpected Error: " + error.getMessage());
        throw new RuntimeException("Unexpected Error: " + error.getMessage());
    }

    public record GoogleTokenResponse(

            @SerializedName("refresh_token_issued_at") String refreshTokenIssuedAt,
            @SerializedName("refresh_token_status") String refreshTokenStatus,
            @SerializedName("expires_in") String expiresIn,
            @SerializedName("token_type") String tokenType,
            @SerializedName("refresh_token") String refreshToken,
            @SerializedName("client_id") String clientId,
            @SerializedName("access_token") String accessToken,
            @SerializedName("refresh_token_expires_in") String refreshTokenExpiresIn,
            @SerializedName("refresh_count") String refreshCount
    ) {}
    public record InputObject (String idpRefreshToken, String thirdPartyIdp) implements Serializable {}
//
//    public static class InputObject implements Serializable {
//        @Serial
//        private static final long serialVersionUID = 3189258800688527467L;
//        private String idpRefreshToken;
//        private String thirdPartyIdp;
//
//        public InputObject (){
//        }
////        public InputObject(String json) {
////            Gson gson = new Gson();
////            InputObject request = gson.fromJson(json, InputObject.class);
////            this.idpRefreshToken = request.getIdpRefreshToken();
////            this.thirdPartyIdp = request.getThirdPartyIdp();
////        }
//
//
//
//
//
//        public String getIdpRefreshToken() {
//            return idpRefreshToken;
//        }
//
//        public String getThirdPartyIdp() {
//            return thirdPartyIdp;
//        }
//
//        public void setIdpRefreshToken(String idpRefreshToken) {
//            this.idpRefreshToken = idpRefreshToken;
//        }
//
//        public void setThirdPartyIdp(String thirdPartyIdp) {
//            this.thirdPartyIdp = thirdPartyIdp;
//        }
//
//        @Override
//        public String toString() {
//            StringBuilder sb = new StringBuilder();
//            sb.append("{");
//            if (this.thirdPartyIdp != null) {
//                sb.append("thirdPartyIdp: ").append(this.getThirdPartyIdp()).append(",");
//            }
//            if (this.idpRefreshToken != null) {
//                sb.append("idpRefreshToken: ").append(this.getIdpRefreshToken());
//            }
//            sb.append("}");
//            return sb.toString();
//        }
//
//        @Override
//        public boolean equals(Object o) {
//            if (this == o) return true;
//            if (!(o instanceof InputObject that)) return false;
//            return Objects.equals(getIdpRefreshToken(), that.getIdpRefreshToken()) && Objects.equals(getThirdPartyIdp(), that.getThirdPartyIdp());
//        }
//
//        @Override
//        public int hashCode() {
//            return Objects.hash(getIdpRefreshToken(), getThirdPartyIdp());
//        }
//
//
//        //        @Override
////        public String toString() {
////            Gson gson = new GsonBuilder().setPrettyPrinting().create();
////            return gson.toJson(this);
////        }
//    }
}
