package in.sb.spring.security.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthResponseDto
{
    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("access_token_expiry")
    private int accessTokenExpiry;

    @JsonProperty("token_type")
    private String tokenType;

    @JsonProperty("user_name")
    private String userName;

    public AuthResponseDto(String accessToken, int accessTokenExpiry, String tokenType, String userName) {
        this.accessToken = accessToken;
        this.accessTokenExpiry = accessTokenExpiry;
        this.tokenType = tokenType;
        this.userName = userName;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public int getAccessTokenExpiry() {
        return accessTokenExpiry;
    }

    public void setAccessTokenExpiry(int accessTokenExpiry) {
        this.accessTokenExpiry = accessTokenExpiry;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    @Override
    public String toString() {
        return "AuthResponseDto{" +
                "accessToken='" + accessToken + '\'' +
                ", accessTokenExpiry=" + accessTokenExpiry +
                ", tokenType='" + tokenType + '\'' +
                ", userName='" + userName + '\'' +
                '}';
    }
}
