package com.mao.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.Map;

/**
 * Author: lloam
 * Date: 2021/9/16 22:55
 * Description: JWT 包装工具类
 */
public class JWTUtil {

    public static final String SIGN = "!@#$%REW";


    /**
     * 生成 token
     * @param map
     * @return
     */
    public static String getToken(Map<String, String> map) {

        Calendar instance = Calendar.getInstance();
        instance.add(Calendar.DATE, 7);

        // 创建 jwt builder
        JWTCreator.Builder builder = JWT.create();

        // payload
        map.forEach((k, v) -> {
            builder.withClaim(k, v);
        });

        String token = builder.withExpiresAt(instance.getTime()) // 过期时间
                .sign(Algorithm.HMAC256(SIGN)); // 签名
        return token;
    }

    /**
     * 验证 token 的合法性
     * @param token
     */
    public static DecodedJWT verify(String token) {
        return JWT.require(Algorithm.HMAC256(SIGN)).build().verify(token);
    }


//    /**
//     * 获取 token 信息方法
//     * @param token
//     * @return
//     */
//    public static DecodedJWT getTokenInfo(String token) {
//        DecodedJWT verify = JWT.require(Algorithm.HMAC256(SIGN)).build().verify(token);
//        return verify;
//    }

}
