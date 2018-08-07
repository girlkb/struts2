## Struts2_Jakarta_Plugin插件远程代码执行漏洞(S2-045) 环境

### 漏洞信息

- [S2-045 公告](https://cwiki.apache.org/confluence/display/WW/S2-045)

### 获取环境:

1.  使用S2-032的war包测试

#### PoC

运行 `poc.py`

```
$ python poc.py <url> <cmd>
```

[![img](https://github.com/Medicean/VulApps/raw/master/s/struts2/s2-045/s2-045-1.png)](https://github.com/Medicean/VulApps/blob/master/s/struts2/s2-045/s2-045-1.png)