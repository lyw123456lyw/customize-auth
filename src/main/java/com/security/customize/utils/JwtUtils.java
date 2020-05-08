package com.security.customize.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.security.customize.jwt.Payload;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.*;

@Component
@PropertySource("classpath:application.yaml")
@ConfigurationProperties(prefix = "jwt")
@Data
public class JwtUtils {
    @Value("secret")
    private String secret;
    @Value("issuer")
    private String issuer;
    @Value("subject")
    private String subject;
    @Value("audience")
    private String audience;
    private Map<String,String> claims;//自定义签名

    /**
     * 创建 hour小时后过期的Token
     * @param claims
     * @param hour
     * @return
     */
    public  String createToken(Map<String,String> claims,int hour) {
        Payload createPayload = this.createPayload(1);
        createPayload.setClaims(claims);
        Algorithm hmac256 = Algorithm.HMAC256(this.getSecret());
        return createToken(createPayload,hmac256);
    }
    /**
     * 根据负载和算法创建Token
     * @param payload
     * @param algorithm
     * @return
     */
    public  String createToken(Payload payload,Algorithm algorithm) {

        JWTCreator.Builder headBuilder = createHeaderBuilder(algorithm);
        JWTCreator.Builder publicClaimbuilder = addPublicClaimBuilder(headBuilder,payload);
        JWTCreator.Builder privateClaimbuilder = addPrivateClaimbuilder(publicClaimbuilder,payload);
        String token = privateClaimbuilder.sign(algorithm);
        return token;
    }
    /**
     * 创建自定小时后过期的负载
     * @param hour
     * @return
     */
    public Payload createPayload(int hour) {
        Payload payload = new Payload();
        payload.setIssuer(this.getIssuer());
        payload.setSubject(this.getSubject());
        payload.setAudience(this.getAudience());
        this.setIssuedAtAndExpiresAt(new Date(), hour, payload);
        return payload;
    }
    /**
     * 创建自定小时后过期的负载
     * @param hour
     * @return
     */
    public Payload createPayload(String issuer, String subject, String audience, Date date,int hour) {
        Payload payload = new Payload();
        payload.setIssuer(issuer);
        payload.setSubject(subject);
        payload.setAudience(audience);
        this.setIssuedAtAndExpiresAt(date, hour, payload);
        return payload;
    }
    /**
     * 添加私有声明
     * @param builder
     * @param payload
     * @return
     */
    private JWTCreator.Builder addPrivateClaimbuilder(JWTCreator.Builder builder, Payload payload) {
        Map<String, String> claims = payload.getClaims();
        if(!CollectionUtils.isEmpty(claims)) {
            claims.forEach((k,v)->{
                builder.withClaim(k, (String) v);
            });
        }
        return builder;
    }
    /**
     * 添加公共声明
     * @param builder
     * @param payload
     * @return
     */
    private JWTCreator.Builder addPublicClaimBuilder(JWTCreator.Builder builder, Payload payload) {
        if(!StringUtils.isEmpty(payload.getIssuer())) {
            builder.withIssuer(payload.getIssuer());
        }

        if(!StringUtils.isEmpty(payload.getSubject())) {
            builder.withSubject(payload.getSubject());
        }

        if(payload.getIssuedAt() != null) {
            builder .withIssuedAt(payload.getIssuedAt()); //生成签名的时间
        }

        if(payload.getExpiresAt() != null) {
            builder .withExpiresAt(payload.getExpiresAt());//签名过期的时间
        }

        if(CollectionUtils.isEmpty(payload.getAudience())) {
            payload.getAudience().forEach((s)->{
                builder.withAudience(s);
            });
        }

        return builder;
    }
    /**
     * 创建JWT 头部信息
     * @param algorithm
     * @return
     */
    private JWTCreator.Builder createHeaderBuilder(Algorithm algorithm) {
        JWTCreator.Builder builder = JWT.create().withHeader(buildJWTHeader(algorithm));
        return builder;
    }
    /**
     * 校验Token
     * @param token
     * @return
     */
    public Payload verifyToken(String token) {
        DecodedJWT jwt = null;
        Payload payload = null;
        try {
            jwt = getDecodedJWT(token);
            payload = getPublicClaim(jwt);
            payload = getPrivateClaim(jwt, payload);
        }catch (AlgorithmMismatchException e) {
            throw e;
        }catch (TokenExpiredException e) {
            throw e;
        } catch (Exception e) {
            throw e;
        }
        return payload;
    }
    /**
     * 获取JWT 私有声明
     * @param jwt
     * @param payload
     * @return
     */
    private Payload getPrivateClaim(DecodedJWT jwt, Payload payload) {
        Map<String, String> claims = new HashMap<String, String>();
        jwt.getClaims().forEach((k,v)->{
            String asString = v.asString();
            claims.put(k, asString);
        });
        payload.setClaims(claims);
        return payload;
    }
    /**
     * 获取JWT 公共声明
     * @param jwt
     * @return
     */
    private Payload getPublicClaim(DecodedJWT jwt) {
        Payload payload = new Payload();
        payload.setIssuer(jwt.getIssuer());
        payload.setSubject(jwt.getSubject());
        payload.setAudience(jwt.getAudience());
        payload.setIssuedAt(jwt.getIssuedAt());
        payload.setExpiresAt(jwt.getExpiresAt());
        return payload;
    }
    /**
     * 获取 DecodedJWT
     * @param token
     * @return
     */
    private DecodedJWT getDecodedJWT(String token) {
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(this.getSecret())).build();
        DecodedJWT jwt = verifier.verify(token);
        return jwt;
    }
    /**
     * 构建JWT头部Map信息
     * @param algorithm
     * @return
     */
    private Map<String, Object> buildJWTHeader(Algorithm algorithm) {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("alg", algorithm.getName());
        map.put("typ", "JWT");
        return map;
    }

    /**
     * 根据发布时间设置过期时间
     * @param issuedAt
     * @param hour
     * @param payload
     */
    public void setIssuedAtAndExpiresAt(Date issuedAt,Integer hour,Payload payload) {
        payload.setIssuedAt(issuedAt);
        payload.setExpiresAt(getAfterDateByHour(issuedAt,hour));
    }
    /**
     * 返回一定时间后的日期
     * @param date 开始计时的时间
     * @param year 增加的年
     * @param month 增加的月
     * @param day 增加的日
     * @param hour 增加的小时
     * @param minute 增加的分钟
     * @param second 增加的秒
     * @return
     */
    public  Date getAfterDateByHour(Date date, int hour){
        if(date == null){
            date = new Date();
        }
        Date afterDate = getAfterDate(date,0,0,0,hour,0,0);
        return afterDate;
    }
    public  Date getAfterDateByMinute(Date date, int minute){
        if(date == null){
            date = new Date();
        }
        Date afterDate = getAfterDate(date,0,0,0,0,minute,0);
        return afterDate;
    }
    /**
     * 返回一定时间后的日期
     * @param date 开始计时的时间
     * @param year 增加的年
     * @param month 增加的月
     * @param day 增加的日
     * @param hour 增加的小时
     * @param minute 增加的分钟
     * @param second 增加的秒
     * @return
     */
    public  Date getAfterDate(Date date, int year, int month, int day, int hour, int minute, int second){
        if(date == null){
            date = new Date();
        }

        Calendar cal = new GregorianCalendar();

        cal.setTime(date);
        if(year != 0){
            cal.add(Calendar.YEAR, year);
        }
        if(month != 0){
            cal.add(Calendar.MONTH, month);
        }
        if(day != 0){
            cal.add(Calendar.DATE, day);
        }
        if(hour != 0){
            cal.add(Calendar.HOUR_OF_DAY, hour);
        }
        if(minute != 0){
            cal.add(Calendar.MINUTE, minute);
        }
        if(second != 0){
            cal.add(Calendar.SECOND, second);
        }
        return cal.getTime();
    }
}
