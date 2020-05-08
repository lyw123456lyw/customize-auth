package com.security.customize.mapper;

import com.security.customize.entity.User;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

public interface UserMapper {
    @Select("select * from sys_user where username = #{username}")
    User findUserByUsername(@Param("username") String userName);
}
