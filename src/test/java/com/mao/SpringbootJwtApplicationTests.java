package com.mao;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

@SpringBootTest
class SpringbootJwtApplicationTests {

    @Test
    void contextLoads() {

        Map<String, Object> map = new HashMap<>();

//        map.put("alg","HMAC256");
//        map.put("typ","JWT");

        Calendar instance = Calendar.getInstance();
        instance.add(Calendar.SECOND, 600);

        String token = JWT.create()
//                .withHeader(map) // header 一般使用默认值，也就是不指定即可
                // 这里指定 payload 的时候注意，存储的 value 是什么类型的值，取出来的时候还是要以相同类型取出
                .withClaim("userId", 21) // payload
                .withClaim("username", "小明")
                .withExpiresAt(instance.getTime())  // 过期时间
                .sign(Algorithm.HMAC256("token!@#HE!#$"));// 签名

        System.out.println(token);
    }


    @Test
    public void test() {
        // 创建验证对象
        JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256("token!@#HE!#$")).build();

        DecodedJWT decodedJWT = jwtVerifier.verify("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MzE4MDQxMTcsInVzZXJJZCI6MjEsInVzZXJuYW1lIjoi5bCP5piOIn0.G46i3SEHTcCvmhkxCNMGSSNddMwzVOACBRRT8r-Y244");

        System.out.println(decodedJWT.getClaim("userId").asInt());
        System.out.println(decodedJWT.getClaim("username").asString());
        System.out.println("过期时间：" + decodedJWT.getExpiresAt());

    }

}
