package com.jtexplorer.aop.aspect;

import com.alibaba.fastjson.JSON;

import com.jtexplorer.aop.annotation.CatchInjection;
import com.jtexplorer.entity.JkExceptionInfo;
import com.jtexplorer.redis.MyLogRedisCache;
import com.jtexplorer.utils.LogTimeTools;
import com.jtexplorer.utils.WxCpSendMsgUtil;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
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
    @Pointcut("@annotation(com.jtexplorer.aop.annotation.CatchException)")
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
        String client = catchInjection.client();
        String injectionMmethod = catchInjection.method();
        String entityType = catchInjection.entityType();
        boolean isAlarm = catchInjection.isAlarm();
        boolean running = catchInjection.running();

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
        boolean checkResult = checkParam(map);
        if (checkResult) {
            try {
                if (running) {
                    result = joinPoint.proceed();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            String dateStr = LogTimeTools.transformDateFormat(jkExceptionInfo.getJkExceDbCreateTime(), "yyyy-MM-dd HH:mm:ss");
            String redisKey = "SQLInjection_jkExceptionInfo_" + projectName + "_" + jkExceptionInfo.getJkExceClassName() + "_" + jkExceptionInfo.getJkExecMethodRemark() + "_" + dateStr;
            redisCache.setCacheObject(redisKey, jkExceptionInfo);
            if (isAlarm) {
                //发送告警信息
                StringBuilder stringBuilder = new StringBuilder();
                stringBuilder.append("SQL注入攻击拦击" + "\n");
                stringBuilder.append("被攻击的SQL" + catchInjection.remark() + "\n");
                stringBuilder.append("注入攻击参数" + paramJson + "\n");
                if (attributes != null) {
                    //接收到请求，记录请求内容
                    HttpServletRequest request = attributes.getRequest();
                    stringBuilder.append("攻击者IP" + request.getRemoteAddr() + "\n");
                }
                wxCpSendMsgUtil.sendTextMsg(stringBuilder.toString());
            }

        }
        return result;
    }

   

    private boolean checkParam(Map<Object, Object> map) {
        final boolean[] flag = {true};
        List<String> specials = new ArrayList<>();
        specials.add("%");
        specials.add("#");
        specials.add("$");
        List<String> attention = new ArrayList<>();
        attention.add("and");
        attention.add("or");
        if (map.isEmpty()){
            map.forEach((k,v)->{
                if (!k.equals("query")){
                    return;
                }
                Class<QueryEntuty> qu = null;
                java.util.List<QueryEntuty> quList =    JsonFormatUtil.stringToArrayList(String.valueOf(v), qu);
                if (ListUtil.isEmpty(quList)){
                    return;
                }
                quList.forEach(o->{
                    if (o.getEmptyOfWhere().isEmpty()) {
                        attention.forEach(a->{
                            if (o.getSqlSegment().equals(a)){
                                flag[0] = false;
                                return;
                            }
                        });
                    }else {
                        specials.forEach(a->{
                            if (o.getSqlSegment().equals(a)){
                                flag[0] = false;
                                return;
                            }
                        });
                    }
                });
            });
        }
        return flag[0];
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
