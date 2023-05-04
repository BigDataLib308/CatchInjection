package com.jtexplorer.aop.annotation;

public @interface CatchInjection {

    String client() default "";

    String remark();

    String method() default "";


    String entityType() default "";

    boolean isAlarm() default true;

    boolean running() default false;

}
