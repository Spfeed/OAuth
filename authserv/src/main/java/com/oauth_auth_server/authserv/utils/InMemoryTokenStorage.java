package com.oauth_auth_server.authserv.utils;

import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemoryTokenStorage {

    //Хранилище для токенов: refreshToken и clientId
    private final ConcurrentHashMap<String, String> refreshTokens = new ConcurrentHashMap<>();

    public void addRefreshToken(String clientId, String refreshToken) {
        refreshTokens.put(refreshToken, clientId);
    }
    //Валдиадция refreshToken, пришедшего с клиента
    public boolean isValidRefreshToken(String refreshToken) {
        return refreshTokens.containsKey(refreshToken);
    }
}
