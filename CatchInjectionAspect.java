package com.qq.aop.aspect;

import com.alibaba.fastjson.JSON;
import com.jtexplorer.entity.JkExceptionInfo;
import com.jtexplorer.redis.MyLogRedisCache;
import com.jtexplorer.utils.*;
import com.qq.aop.annotation.CatchInjection;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.annotation.*;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class CatchInjectionAspect {


    private long currentTime;
    private long startTime;
    private long endTime;

    private Map<String, String> map = new HashMap<>();

    @Resource
    private MyLogRedisCache redisCache;
    @Resource
    private WxCpSendMsgUtil wxCpSendMsgUtil;
    @Value("${Config.Log.projectName}")
    private String projectName;

    /**
     * 切入点标明作用在所有注解的方法上
     */
    @Pointcut("@annotation(com.qq.aop.annotation.CatchException)")
    public void cutPoint() {
    }

    /**
     * 前置操作：目标执行之前执行
     *
     * @param joinPoint
     */
    @Before("cutPoint()")
    public void Before(JoinPoint joinPoint) throws ParseException {
        currentTime = System.currentTimeMillis();
        startTime = System.currentTimeMillis();
    }

    /**
     * 环绕操作：环绕目标方法执行
     *
     * @param joinPoint
     * @return
     * @throws Throwable
     */
    @Around("cutPoint()")
    public Object Around(ProceedingJoinPoint joinPoint) throws Throwable {
        Object result = null;
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

        JkExceptionInfo jkExceptionInfo = new JkExceptionInfo();
        Signature signature = joinPoint.getSignature();
        String semeMethod = signature.getDeclaringTypeName() + "." + signature.getName();
        jkExceptionInfo.setJkExceMessage(semeMethod);
        MethodSignature methodSignature = ((MethodSignature) joinPoint.getSignature());
        Method method = methodSignature.getMethod();
        CatchInjection catchInjection = method.getAnnotation(CatchInjection.class);
        jkExceptionInfo.setJkExecMethodRemark(catchInjection.remark());
        Object[] args = joinPoint.getArgs();
        DefaultParameterNameDiscoverer discoverer = new DefaultParameterNameDiscoverer();
        String[] parameterNames = discoverer.getParameterNames(method);
        Map<Object, Object> map = new HashMap<>();
        for (int i = 0; i < parameterNames.length; i++) {
            map.put(parameterNames[i], args[i]);
        }
        //map转json
        String paramJson = JSON.toJSONString(map);
        jkExceptionInfo.setJkExecParamsJson(paramJson);
        String className = joinPoint.getTarget().getClass().getSimpleName() + "[" + joinPoint.getSignature().getName() + "]";
        jkExceptionInfo.setJkExceClassName(className);
        jkExceptionInfo.setJkExceDbCreateTime(new Date());
        boolean checkResult = checkParam(paramJson);
        if (checkResult) {
            try {
                result = joinPoint.proceed();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }else {
            String dateStr = LogTimeTools.transformDateFormat(jkExceptionInfo.getJkExceDbCreateTime(), "yyyy-MM-dd HH:mm:ss");
            String redisKey = "SQLInjection_jkExceptionInfo_" + projectName + "_" + jkExceptionInfo.getJkExceClassName() + "_" + jkExceptionInfo.getJkExecMethodRemark() + "_" + dateStr;
            redisCache.setCacheObject(redisKey, jkExceptionInfo);
            //发送告警信息
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append("SQL注入攻击拦击" + "\n");
            stringBuilder.append("被攻击的SQL" + catchInjection.remark()+ "\n");
            stringBuilder.append("注入攻击参数" + paramJson+ "\n");
            if (attributes != null) {
                //接收到请求，记录请求内容
                HttpServletRequest request = attributes.getRequest();
                stringBuilder.append("攻击者IP" + request.getRemoteAddr()+ "\n");
            }
            wxCpSendMsgUtil.sendTextMsg(stringBuilder.toString());
        }
        return result;
    }

    private boolean checkParam(String paramJson) {
        return true;
    }

    /**
     * 后置操作:目标方法之后执行（始终执行）
     *
     * @param joinPoint
     * @throws Throwable
     */
    @After("sendLog()")
    public void doAfter(JoinPoint joinPoint) throws Throwable {

    }
}
