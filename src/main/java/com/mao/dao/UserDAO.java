package com.mao.dao;

import com.mao.entity.User;
import org.apache.ibatis.annotations.Mapper;

/**
 * Author: lloam
 * Date: 2021/9/16 23:29
 * Description: dao 接口
 */
@Mapper
public interface UserDAO {

    User login(User user);
}
