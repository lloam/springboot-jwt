package com.mao.service;

import com.mao.dao.UserDAO;
import com.mao.entity.User;
import lombok.experimental.Accessors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Author: lloam
 * Date: 2021/9/16 23:35
 * Description: 实现类
 */
@Service
@Transactional
public class UserServiceImpl implements UserService {

    @Autowired
    private UserDAO userDAO;


    /**
     * 用户登录
     * @param user
     * @return
     */
    @Transactional(propagation = Propagation.SUPPORTS)
    public User login(User user) {
        // 根据接受用户名密码查询数据库
        User userDB = userDAO.login(user);
        if (userDB != null) {
            return userDB;
        }
        throw new RuntimeException("登录失败~~");
    }
}
