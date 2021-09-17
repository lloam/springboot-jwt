# JWT

![image-20210916160125612](https://gitee.com/lloamhh/spring-img/raw/master/img/myTest/202109161601097.png)



## 1.什么是 JWT

JSON Web Token (JWT) is an open standard ([RFC 7519](https://tools.ietf.org/html/rfc7519)) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with the **HMAC** algorithm) or a public/private key pair using **RSA** or **ECDSA**.

```markdown
# 1.翻译
- 官网地址：https://jwt.io/introduction
- 翻译：jsonwebtoken（JWT）是一个开放标准（rfc7519），它定义了一种紧凑的、自包含的方式，用于在各方之间以 JSON 对象安全地传输信息，此信息可以验证和信任，因为他是数字签名的。jwt 可以使用秘密（使用 HMAC 算法）或使用 RSA 或 ECSDA 的公钥/私钥对进行签名
# 2.通俗解释
- JWT 简称 JSON Web Token，也就是通过 JSON 形式作为 Web 应用中的令牌，用于在各方之间安全地将信息作为 JSON 对象传输。在数据传输过程中还可以完成数据加密、签名等相关处理
```



## 2.JWT 能做什么

```markdown
# 1.授权
- 这是使用 JWT 的最常见方案，一旦用户登录，每个后续请求将包括 JWT，从而允许用户访问该令牌允许的路由，服务和资源。单点登录是当今广泛使用 JWT 的一项功能，因为它的开销很小并且可以在不同的域中轻松使用。

# 2.信息交换
- JSOn Web Token 是在各方之间安全地传输信息的好方法。因为可以对 JWT 进行签名（例如，使用公钥、私钥对），所以您可以确保发件人是他们所说的人。此外，由于签名是使用标头和有效负载计算的，因此您还可以验证内容是否遇到篡改。
```



## 3.为什么是 JWT

### 基于传统的 Session 认证

```markdown
# 1.认证方式
- 我们知道，http 协议本身是一种无状态的协议，而这就意味着如果用户向我们的应用提供了用户名和密码来进行用户认证，那么些一次请求时，用户还要再一次进行用户认证才行，因为根据 http 新协议，我们并不能知道是哪个用户发出的请求，所以为了让我们的应用能识别是哪个用户发出的请求，我们只能在服务器存储一份用户登录的信息，这份登录信息会在响应时传递给浏览器，告诉其保存为 cookie，以便下次请求时发送给我们的应用，这样我们的应用就能识别请求来自哪个用户了，这就是传统的基于 session 认证

# 2.认证流程
```

![image-20210916163827110](https://gitee.com/lloamhh/spring-img/raw/master/img/myTest/202109161638451.png) 

```markdown
# 3.暴露问题
- 1.每个用户经过我们的应用认证之后，我们的应用都要在服务端做一次记录，以方便用户下次请求的鉴别，通常而言 session 都是保存在内存中，而随着认证用户的增多，服务端的开销会明显增大

- 2.用户认证之后，服务端做认证记录，如果认证的记录被保存在内存中的话，这意味这用户下次请求还必须要请求在这台服务器上，这样才能拿到授权的资源，这样在分布式的应用上，相应的限制了负载均衡的能力。这也意味着限制了应用的扩展能力。

- 3.因为是基于 cookie 来进行用户识别的，cookie 如果被截获，用户就会很容易收到跨站请求伪造的攻击。

- 4.在前后端分离系统中就更加痛苦：如下图所示
	也就是说前后端分离在应用解耦后增加了部署的复杂性。通常用户一次请求就要转发多次。如果用 session 每次携带sessionid 到服务器，服务器还要查询用户信息。同时如果用户很多，这些信息存储在服务器内存中，给服务器增加负担，还有就是 CSRF（跨站伪造请求攻击）攻击，session 是基于 cookie 进行用户识别的，cookie 如果被截获，用户就会很容易受到跨站请求伪造的攻击。还有就是 sessionid 就是一个特征值，表达的信息不够丰富。不容易扩展。而且如果后端应用时多节点部署，那么就需要实现 session 共享机制，不方便集群应用。
```

![image-20210916165138783](https://gitee.com/lloamhh/spring-img/raw/master/img/myTest/202109161651333.png) 

### 基于 JWT 认证

![image-20210916165358416](https://gitee.com/lloamhh/spring-img/raw/master/img/myTest/202109161654250.png) 

```markdown
# 1.认证流程
- ⾸先，前端通过 Web 表单将⾃⼰的⽤⼾名和密码发送到后端的接⼝。这⼀过程⼀般是⼀个 HTTP POST请求。建议的⽅式是通过SSL加密的传输(https协议) ，从⽽避免敏感信息被嗅探。

- 后端核对⽤户名和密码成功后，将⽤户的 id 等其他信息作为 JWT Payload (负载)，将其与头部分别进⾏ Base64 编码拼接后签名，形成⼀个JWT(Token)。形成的JWT就是⼀个形同 11. zzz. xxx 的字符串。token head.payload.signature

- 后端将 JWT 字符串作为登录成功的返回结果返回给前端。 前端可以将返回的结果保存在 localStorage 或 sessionStorage 上， 退出登录时前端删除保存的JWT即可。

- 前端在每次请求时将 JWT 放⼊ HTTP Header 中的 Authorization 位。 (解决XSS和XSRF问题)

- 后端检查是否存在，如存在验证 JWT 的有效性。
	- 检查签名是否正确
	- 检查 Token 是否过期;
	- 检查 Token 的接收⽅是否是⾃⼰(可选)
	
- 验证通过后后端使⽤ JWT 中包含的用户信息进⾏其他逻辑操作，返回相应结果。

# 2.JWT 优势在哪？
- 简洁(Compact): 可以通过 URL，POST 参数或者在 HTTP header 发送，数据量⼩，传输速度快
-  ⾃包含(Self-contained):负载中包含了所有⽤⼾所需要的信息，避免了多次查询数据库
- 因为 Token 是以 JSON 加密的形式保存在客⼾端的，所以 JWT 是跨语⾔的，原则上任何web形式都⽀持。
- 不需要在服务端保存会话信息，特别适⽤于分布式微服务。
```



## 4.JWT 的结构是什么？

```markdown
token	string =====> header.payload.signature
# 1.令牌组成
- 1.标头（Header）
- 2.有效载荷（Payload）
- 3.签名（Signature）
- 因此，JWT 通常如下所示：xxxxx.yyyyy.zzzzz	Header.Payload.Signature

# 2.Header
- 标头通常由两部分组成：令牌的类型（即 JWT）和所使用的签名算法，例如 HMAC SHA256 或 RSA。它会使用 Base64 编码组成 JWT 结构的第一部分。

- 注意：Base64 是一种编码，也就是说，它时可以被翻译会原来的样子来的。它并不是一种加密过程。
```

```json
{
    "alg": "HS256",
    "typ": "JWT"
}
```

```markdown
# 3.Payload
- 令牌的第二部分是有效负载，其中包含声明。声明是有关实体（通常是用户）和其他数据的声明。同样的，他会使用 Base64 编码组成 JWT 结构的第二部分
```

```json
{
    "sub": "123456789",
    "name": "John Doe",
    "admin": true
}
```

```markdown
# 4.Signature
- 前面两部分都是使用 Base64 进行编码的，即前端可以解开知道里面的信息。Signature 需要使用编码后的 header 和 payload 以及我们提供的一个密钥，然后使用 header 中指定的签名算法（HS256）进行签名。签名的作用是保证 JWT 没有被篡改过
- 如：
	HMACSHA256（base64UrlEncode(header) + "." + base64UrlEncode(payload),secret);
	
# 签名目的
- 最后一步签名的过程，实际上是对头部以及负载内容进行签名，防止内容被篡改，如果有人对头部以及负载的内容解码之后进行修改，再进行编码，最后加上之前的签名组合形成新的 JWT 的话，那么服务器端会判断出新的头部和负载形成的签名和 JWT 附带上的签名是不一样的。如果要对新的头部和负载进行签名，在不知道服务器加密时用的密钥的话，的出来的签名也是不一样的。

# 信息安全问题
- 在这里大家一定会问一个问题：Base64 是一种编码，是可逆的，那么我的信息不就被暴露了吗？

- 是的。所以，在 JWT 中，不应该在负载里面加入任何敏感的数据。在上面的例子中，我们传输的时用户的 User ID。这个值实际上不是什么敏感内容，一般情况下被知道也是安全地，但是像密码这样的内容就不能被放在 JWT 中了，如果将用户的密码放在了 JWT 中，那么怀有恶意的第三方通过 Base64 解码就能很快地知道你的密码了。因此 JWT 适合用于向 Web 应用传递一些非敏感信息。JWT 还经常用于设计用户认证和授权系统，甚至实现 Web 应用的单点登录。
```

![image-20210916174841461](https://gitee.com/lloamhh/spring-img/raw/master/img/myTest/202109161748493.png)

```markdown
- 输出是三个由点分割的 Base64-URL 字符串，可以在 HTML 和 HTTP 环境中轻松传递这些字符串，与基于 XML 的标准（例如 SAML）相比，它更紧凑
- 简洁（Compact）
	可以通过 URL，POST 参数或者在 HTTP header 发送，因为数据量小，产地速度快
- 自包含（Self-contained）
	负载中包含了所有用户所需要的信息，避免了多次查询数据库
```

![image-20210916175324103](https://gitee.com/lloamhh/spring-img/raw/master/img/myTest/202109161753862.png)



## 5.使用 JWT

```markdown
# 1.导入依赖
```

```xml
<!-- 引入 jwt 依赖 -->
<!-- https://mvnrepository.com/artifact/com.auth0/java-jwt -->
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>3.10.3</version>
</dependency>
```

````markdown
# 2.生成 token
````

```java
Map<String, Object> map = new HashMap<>();

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
```

```markdown
- 生成结果
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MzE4MDMxOTcsInVzZXJJZCI6MjEsInVzZXJuYW1lIjoi5bCP5piOIn0.LHxNrLKLBJt56ZH2-uzSkiiXZ_6GKjoO8a8hYTXUgQk
```

```markdown
# 3.根据令牌和签名解析数据
```

```java
// 创建验证对象
JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256("token!@#HE!#$")).build();

DecodedJWT decodedJWT = jwtVerifier.verify("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MzE4MDMxOTcsInVzZXJJZCI6MjEsInVzZXJuYW1lIjoi5bCP5piOIn0.LHxNrLKLBJt56ZH2-uzSkiiXZ_6GKjoO8a8hYTXUgQk");

System.out.println(decodedJWT.getClaim("userId").asInt());
System.out.println(decodedJWT.getClaim("username").asString());
System.out.println("过期时间：" + decodedJWT.getExpiresAt());
```

```markdown
# 4.常见异常信息
- SignatureVerificationException：		签名不一致异常
- TokenExpiredException:				 令牌过期异常
- AlgorithmMismatchException：			算法不匹配异常
- InvalidClaimException:				 失效的 payload 异常
```

![image-20210916224853208](https://gitee.com/lloamhh/spring-img/raw/master/img/myTest/202109162248772.png)





## 6.封装工具类

```java
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
```



## 7.整合 springboot

```markdown
# 0.搭建 springboot + mybatis + jwt 环境
- 引入依赖
- 编写配置
```

```xml
<dependencies>

    <!-- 引入 jwt 依赖 -->
    <!-- https://mvnrepository.com/artifact/com.auth0/java-jwt -->
    <dependency>
        <groupId>com.auth0</groupId>
        <artifactId>java-jwt</artifactId>
        <version>3.10.3</version>
    </dependency>

    <!-- 引入 mybatis -->
    <dependency>
        <groupId>org.mybatis.spring.boot</groupId>
        <artifactId>mybatis-spring-boot-starter</artifactId>
        <version>2.1.3</version>
    </dependency>

    <!-- 引入 lombok -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
    </dependency>

    <!-- 引入 druid -->
    <dependency>
        <groupId>com.alibaba</groupId>
        <artifactId>druid</artifactId>
        <version>1.2.5</version>
    </dependency>

    <!-- 引入 mysql -->
    <dependency>
        <groupId>mysql</groupId>
        <artifactId>mysql-connector-java</artifactId>
    </dependency>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>
```



```yml
server:
  port: 8989
spring:
  datasource:
    type: com.alibaba.druid.pool.DruidDataSource
    username: root
    password: 123456
    url: jdbc:mysql://localhost:3306/jwt?serverTimezone=UTC&useUnicode=true&characterEncoding=utf-8
    driver-class-name: com.mysql.cj.jdbc.Driver

mybatis:
  type-aliases-package: com.mao.entity
  mapper-locations: classpath:mybatis/mapper/*.xml

logging:
  level:
    com.mao.dao: debug

```

```markdown
# 1.开发数据库
- 这里采用最简单的表结构验证 JWT 使用
```

![image-20210916232403873](https://gitee.com/lloamhh/spring-img/raw/master/img/myTest/202109162324169.png)



```sql
CREATE TABLE `jwt`.`user` (
    `id` INT NOT NULL AUTO_INCREMENT COMMENT '主键 id', 
    `username` VARCHAR(255) COMMENT '用户名', 
    `password` VARCHAR(255) COMMENT '密码', 
    PRIMARY KEY (`id`) 
) ENGINE=INNODB CHARSET=utf8; 
```



```markdown
# 2.开发 entity
```

```java
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
```

```markdown
# 3.开发 DAO 接口和 Mapper.xml
```

```java
/**
 * Author: lloam
 * Date: 2021/9/16 23:29
 * Description: dao 接口
 */
@Mapper
public interface UserDAO {

    User login(User user);
}

```

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Config 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.mao.dao.UserDAO">

    <select id="login" resultType="com.mao.entity.User" parameterType="com.mao.entity.User">
        select * from user where username = #{username} and password = ${password}
    </select>

</mapper>
```

```markdown
# 4.开发 Service 接口以及实现类
```

```java
/**
 * Author: lloam
 * Date: 2021/9/16 23:34
 * Description: service 接口
 */
public interface UserService {

    User login(User user); // 登录接口
}
```

```java
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
```



```markdown
# 5.开发 controller
```

```java
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
            payload.put("id", String.valueOf(userDB.getId()));
            payload.put("name", userDB.getUsername());
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
}
```

```markdown
# 6.添加数据并启动项目
```



![image-20210917212256688](https://gitee.com/lloamhh/spring-img/raw/master/img/myTest/202109172123034.png)



```markdown
# 7.通过 postman 模拟登录失败
```

![image-20210917212605930](https://gitee.com/lloamhh/spring-img/raw/master/img/myTest/202109172126279.png)



```markdown
# 8.通过 postman 模拟登录成功
```

![image-20210917212813922](https://gitee.com/lloamhh/spring-img/raw/master/img/myTest/202109172128370.png)

```markdown
# 9.编写测试接口
```

```java
@PostMapping("/user/test")
public Map<String, Object> test(String token) {
    Map<String, Object> map = new HashMap<>();
    log.info("当前的 token 为：【{}】", token);
    try {
        DecodedJWT verify = JWTUtil.verify(token);
        map.put("state", true);
        map.put("msg", "请求成功");
        return map;
    } catch (SignatureVerificationException e) {
        e.printStackTrace();
        map.put("msg", "无效签名");
    } catch (TokenExpiredException e) {
        e.printStackTrace();
        map.put("msg", "token 过期");
    } catch (AlgorithmMismatchException e) {
        e.printStackTrace();
        map.put("msg", "token 算法不一致");
    } catch (Exception e) {
        e.printStackTrace();
        map.put("msg", "token 无效");
    }
    map.put("state", false);
    return map;
}
```



```markdown
# 10.通过 postman 请求接口
```

![image-20210917213119330](https://gitee.com/lloamhh/spring-img/raw/master/img/myTest/202109172131721.png)

![image-20210917213220103](https://gitee.com/lloamhh/spring-img/raw/master/img/myTest/202109172132507.png)



```markdown
# 11.问题？
- 使用上述方式每次都要传递 token 数据，每个方法都需要验证 token 代码冗余，不够灵活？如何优化
- 使用拦截器进行优化
```

`JWTInterceptor.java`

```java
/**
 * Author: lloam
 * Date: 2021/9/17 21:44
 * Description: 拦截请求验证 JWT 是否有效
 */
@Component
public class JWTInterceptor implements HandlerInterceptor {

    /**
     * 验证 token
     * @param request
     * @param response
     * @param handler
     * @return
     * @throws Exception
     */
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 获取请求头中的令牌 token
        String token = request.getHeader("token");
        Map<String, Object> map = new HashMap<>();
        try {
            // 验证 token
            JWTUtil.verify(token);
            return true;
        } catch (SignatureVerificationException e) {
            e.printStackTrace();
            map.put("msg", "无效签名");
        } catch (TokenExpiredException e) {
            e.printStackTrace();
            map.put("msg", "token 已过期");
        } catch (AlgorithmMismatchException e) {
            e.printStackTrace();
            map.put("msg", "算法不一致");
        } catch (Exception e) {
            e.printStackTrace();
            map.put("msg", "token 无效");
        }
        // 设置状态
        map.put("state", false);
        // 将 map 转换成 json 返回给前端
        String json = new ObjectMapper().writeValueAsString(map);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().println(json);
        return false;
    }
}
```

`InterceptorConfig,java`

```java
/**
 * Author: lloam
 * Date: 2021/9/17 22:00
 * Description: WebMvc 配置类
 */
@Configuration
public class InterceptorConfig implements WebMvcConfigurer {

    @Autowired
    private JWTInterceptor jwtInterceptor;

    /**
     * 添加拦截器
     * @param registry
     */
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new JWTInterceptor())
                .addPathPatterns("/user/*")             // 拦截所有请求
                .excludePathPatterns("/user/login");    // 除了用户的登录请求放行
    }
}
```

![image-20210917222245664](https://gitee.com/lloamhh/spring-img/raw/master/img/myTest/202109172222857.png)

































