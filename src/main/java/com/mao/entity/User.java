package com.mao.entity;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * Author: lloam
 * Date: 2021/9/16 23:28
 * Description: 用户实体类
 */
@Data
@Accessors(chain = true)
public class User {

    private Integer id;
    private String username;
    private String password;
}
