package com.mao.controller;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.mao.entity.User;
import com.mao.service.UserService;
import com.mao.utils.JWTUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * Author: lloam
 * Date: 2021/9/16 23:38
 * Description: 控制层
 */
@RestController
@Slf4j
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/user/login")
    public Map<String, Object> login(User user) {
        log.info("用户名：【{}】",user.getUsername());
        log.info("密码：【{}】",user.getPassword());
        Map<String, Object> map = new HashMap<>();
        try {
            User userDB = userService.login(user);
            Map<String, String> payload = new HashMap<>();
            payload.put("userId", String.valueOf(userDB.getId()));
            payload.put("username", userDB.getUsername());
            // 生成 JWT 的令牌
            String token = JWTUtil.getToken(payload);
            map.put("state",true);
            map.put("msg","认证成功");
            map.put("token", token);
        } catch (Exception e) {
            map.put("state", false);
            map.put("msg", e.getMessage());
        }
        return map;
    }


    @PostMapping("/user/test")
    public Map<String, Object> test(HttpServletRequest request) {
        Map<String, Object> map = new HashMap<>();
        // 处理自己业务逻辑
        // 获取 token
        String token = request.getHeader("token");
        // 获取 token 中的 payload 负载的个人信息
        DecodedJWT verify = JWTUtil.verify(token);
        String userId = verify.getClaim("userId").asString();
        String username = verify.getClaim("username").asString();
        log.info("用户 id：【{}】", userId);
        log.info("用户姓名：【{}】", username);
        map.put("state", true);
        map.put("msg", "认证成功");
        return map;
    }
}
