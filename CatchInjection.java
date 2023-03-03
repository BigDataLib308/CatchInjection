package com.qq.aop.annotation;

import java.util.List;

public @interface CatchInjection {

    String client() default "";

    String remark();

    String method() default "";


    String entityType() default "";

    boolean isAlarm() default true;

    String running() default "";

}
