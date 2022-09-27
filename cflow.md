# cdep

```
# 开启swap
free -m
dd if=/dev/zero of=/swapfile count=2048 bs=1M
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
vim /etc/fstab
/swapfile none swap sw 0 0

# 解决 WARNING: Your kernel does not support swap limit capabilities. Limitation discarded.
GRUB_CMDLINE_LINUX="cgroup_enable=memory swapaccount=1"
sudo update-grub
```



# cflow

## 运行结果

```sh
git clone https://github.com/xlab-uiuc/cflow.git
cd cflow
mvn compile

# prepare app, e.g. hadoop_common 
wget https://archive.apache.org/dist/hadoop/common/hadoop-3.3.0/hadoop-3.3.0.tar.gz
tar zxvf hadoop-3.3.0.tar.gz

# Run the analysis
./run.sh -a hadoop_common [-i] [-s]
# generate tmp.txt 包含源到接收器的污点传播路径
```

If the `-i` flag is enabled, only intra-procedural analysis in performed, used for testing only.

If the `-s` flag is enabled, the SPARK call graph toolkit is used to compute a more accurate call graph at the cost of longer running time and higher memory consumption.

![image-20220912135054778](https://happytsing-figure-bed.oss-cn-hangzhou.aliyuncs.com/xt/image-20220912135054778.png)

Result From cFlow：

```java
// l1 是 source duration
Source: l1 in l1 = virtualinvoke r0.<org.apache.hadoop.conf.Configuration: long getTimeDuration(java.lang.String,long,java.util.concurrent.TimeUnit)>("hadoop.service.shutdown.timeout", 30L, $r1) in method <org.apache.hadoop.util.ShutdownHookManager: long getShutdownTimeout(org.apache.hadoop.conf.Configuration)> reaches:

// 传播路径
-- Sink l0 in $z0 = interfaceinvoke $r3.<java.util.concurrent.ExecutorService: boolean awaitTermination(long,java.util.concurrent.TimeUnit)>(l0, $r2) in method <org.apache.hadoop.util.ShutdownHookManager: void shutdownExecutor(org.apache.hadoop.conf.Configuration)> along:
    -> l1 in l1 = virtualinvoke r0.<org.apache.hadoop.conf.Configuration: long getTimeDuration(java.lang.String,long,java.util.concurrent.TimeUnit)>("hadoop.service.shutdown.timeout", 30L, $r1) in method <org.apache.hadoop.util.ShutdownHookManager: long getShutdownTimeout(org.apache.hadoop.conf.Configuration)>
    -> [Return] l0 in l0 = staticinvoke <org.apache.hadoop.util.ShutdownHookManager: long getShutdownTimeout(org.apache.hadoop.conf.Configuration)>(r1) in method <org.apache.hadoop.util.ShutdownHookManager: void shutdownExecutor(org.apache.hadoop.conf.Configuration)>
    -> l0 in $z0 = interfaceinvoke $r3.<java.util.concurrent.ExecutorService: boolean awaitTermination(long,java.util.concurrent.TimeUnit)>(l0, $r2) in method <org.apache.hadoop.util.ShutdownHookManager: void shutdownExecutor(org.apache.hadoop.conf.Configuration)>
```

## 论文

Since there is no existing benchmark for taint tracking in cloud systems, we apply cFlow on Hadoop Common and **manually check** the taint propagation path starting from selected configuration loading points. Our preliminary evaluation shows **cFlow can correctly track the flow of configuration options starting from 60 out of 150 inspected sources**, and 73 of the 90 incorrect cases are due to **uncovered library modeling** and **implicit information flow**, which is not supported by design.

也就是说，正确跟踪配置的流的概率只有 `40%`。

cFlow takes as input **Jimple intermediate representation of Java bytecode**, and tracks how configuration options flow through a software system **from** their **loading points to user-specified sinks** such as external API calls. 

Based on the taint analysis, **cFlow starts from source points and generates a directed taint propagation graph.** 

Finally, a path reconstructor module outputs the reconstructed taint propagation paths.

**INPUT**：Jimple中间表示。

**OUTPUT**：生成有向污染传播图，并且路径重构模块输出重构后的污染传播路径。

cFlow将Java字节码的Jimple中间表示作为输入，并跟踪配置选项如何通过软件系统从它们的加载点流向用户指定的汇点(如外部API调用)。基于污染分析，cFlow从源点出发，生成有向污染传播图。最后，路径重构模块输出重构后的污染传播路径。

![image-20220911200937548](https://happytsing-figure-bed.oss-cn-hangzhou.aliyuncs.com/xt/image-20220911200937548.png)

cFlow基于Soot，处理后输出Jimple IR和Call Graph。CFlow提供了 `Source Sink Manager`，用于帮助识别：该语句是source还是sink？

紧接着执行静态污染分析，该分析从配置加载点开始，使用污染分析引擎，跟踪其通过软件系统的传播。

每个受污染对象，用一种叫做 `taint abstraction`的数据结构表示，当来自受污染对象的信息流向另一个对象时，将在二者之间绘制一条有向边。

如此，静态污染分析阶段的输出就是 `Taint Propagation Graph`，最后`Path Reconstructor`对路径重构，输出`Taint Propagation Graph`.

**what is Source and Sink?**

- Taint Sources：配置在加载之后会被存储到系统变量中，这些通过加载初始化的变量，就作为分析的 `initial taints`，其余所有变量都被初始化为未被污染。 识别方法？ 基于源项目的getter/setter方法。作者给出了Hadoop、Hbase、Spark的识别实现。
- Taint Sinks：cFlow允许用户指定如何识别接收语句。默认实现为将几乎所有外部API都视为Sinks。

> ❓Sinks有点疑惑，为啥是所有外部API。

**Taint Propagation**

cFlow formulates taint analysis as a forward dataflow analysis and propagates taint abstractions as dataflow facts in the interprocedural control flow graph (ICFG) of the analyzed program.

给出了污染传播的规则，例如一个Call Flow Function，它从调用方的前一个语句接收传入的污点，并将污点输出到其被调用方的入口节点。

**Path Reconstructor**

污染传播完成后，生成有向污染传播图。为了报告从源到汇的污染传播路径，cFlow遍历污染传播图并重建传播路径。

## 代码

```java
/* Main.java */
srcPaths: [app\hadoop-3.3.0\share\hadoop\common\hadoop-common-3.3.0.jar,app\hadoop-3.3.0\share\hadoop\common\hadoop-kms-3.3.0.jar, app\hadoop-3.3.0\share\hadoop\common\hadoop-nfs-3.3.0.jar, app\hadoop-3.3.0\share\hadoop\common\hadoop-registry-3.3.0.jar]

classPaths: [...]
ISourceSinkManager sourceSinkManager = new SourceSinkManager(configInterface);
ITaintWrapper taintWrapper = TaintWrapper.getDefault();

TaintAnalysisDriver driver = new TaintAnalysisDriver(sourceSinkManager, taintWrapper);

// 开始调用分析
if (run_intra) {
    driver.runIntraTaintAnalysis(srcPaths, classPaths);
} else {
    driver.runInterTaintAnalysis(srcPaths, classPaths, use_spark);
}
```

在Main.java中从命令行、utility/Config中获取了如srcPaths等，构建了：

- sourceSinkManager：获取source 和 sink
- taintWrapper

根据参数，决定分析方式，此处以过程间分析、且使用spark增加精度为例。

```java
/* function: runInterTaintAnalysis @use_spark*/
sootArgs = new String[]{
    // General Options 开启过程间分析
    "-w",

    // Input Options 设置soot自己的classpath，使用-pp找到java的classpath中的必要jar包
    "-cp", classPath,
    "-pp",
    "-allow-phantom-refs",
    "-no-bodies-for-excluded",

    // Output Options 输出Jimple
    "-f", "J",

    // Phase Options 使用spark进行过程间分析（指针分析）
    "-p", "cg", "all-reachable",
    "-p", "cg.spark", "enabled",
    "-p", "cg.spark", "apponly"
    
    // 将srcPaths中的所有目录作为测试目标，将测试这些jar包下所有的类
    "-process-dir", "app\hadoop-3.3.0\share\hadoop\common\hadoop-common-3.3.0.jar",
    "-process-dir", "app\hadoop-3.3.0\share\hadoop\common\hadoop-kms-3.3.0.jar",
    "-process-dir", "app\hadoop-3.3.0\share\hadoop\common\hadoop-nfs-3.3.0.jar",
    "-process-dir", "app\hadoop-3.3.0\share\hadoop\common\hadoop-reqistry-3.3.0.jar",
};

// 在wtjp这个phase中插入一个自定义的subphase，将其命名为 wjtp.taintanalysis
PackManager.v().getPack("wjtp").add(new Transform("wjtp.taintanalysis", new InterAnalysisTransformer(sourceSinkManager, taintWrapper)));

// 运行soot
soot.Main.main(sootArgs);
```

运行soot，并插入了一个subphase，soot会执行，在这个subphase中我们进行污点分析！

```java
public class InterAnalysisTransformer extends SceneTransformer {
    
    private final InterTaintAnalysis analysis;
    
    public InterAnalysisTransformer(ISourceSinkManager sourceSinkManager, ITaintWrapper taintWrapper) {
        this.analysis = new InterTaintAnalysis(sourceSinkManager, taintWrapper);
    }

    
    @Override
    protected void internalTransform(String phaseName, Map<String, String> options) {
        // 1. 污点分析
        analysis.doAnalysis(); 
        
        // 2. 输出结果 原始代码中就是直接sout(Taint.toString()),因此主要改动此处即可
    }
}
```

插入的subphase的类实例，必须继承SceneTransformer或BodyTransformer，前者用于过程间分析，后者用于过程内分析。

且必须实现internalTransform()方法。

但cflow又做了一次抽象，具体的污点分析在InterTaintAnalysis中进行，对于污点分析的结果处理在internalTransform中进行。

```java
public class InterTaintAnalysis {
    
    // 获取所有的方法
    List<SootMethod> methodList = new ArrayList<>();
    for (SootClass sc : Scene.v().getApplicationClasses()) {
        for (SootMethod sm : sc.getMethods()) {
            /*  SootMethod.isConcrete() Returns true if this method is not phantom, abstract or native, i.e.
   				phantom method：是在process directory 和 Soot classpath 都不存在的类，但是被其他类调用，于是soot创建该类，该类中的方法就是phantom method
  				Reference from: https://soot-build.cs.uni-paderborn.de/public/origin/develop/soot/soot-develop/jdoc/ 
  			*/
            if (sm.isConcrete()) {
                methodList.add(sm);
            }
        }
    }

    // 获取所有方法的方法体
    List<Body> bodyList = new ArrayList<>();
    for (SootMethod sm : methodList) {
        Body b = sm.retrieveActiveBody();
        bodyList.add(b);
    }


    // 第一次遍历所有body，以及其内部的所有语句stmt，如果是赋值语句，那么判断它是否是污点源sources，并将其加入sources中。
    int iter = 1;
    for (Body b : bodyList) {
        TaintFlowAnalysis analysis = new TaintFlowAnalysis(b, sourceSinkManager, Taint.getEmptyTaint(),methodSummary, 
                                                           methodTaintCache, taintWrapper);
        analysis.doAnalysis();
        sources.addAll(analysis.getSources());
    }
    iter++;
    
    
    // 开始第二次遍历，经过若干次遍历后，污点分析最终趋于稳定，也就是不在change时，结束污点分析。
    boolean changed = true;
    while (changed) {
        changed = false;
        logger.info("iter {}", iter);

        for (SootMethod sm : methodList) {
            Body b = sm.retrieveActiveBody();
            Set<Taint> entryTaints = new HashSet<>();
            entryTaints.addAll(methodSummary.get(sm).keySet());
            for (Taint entryTaint : entryTaints) {
                TaintFlowAnalysis analysis = new TaintFlowAnalysis(b, sourceSinkManager, entryTaint,
                                                                   methodSummary, methodTaintCache, taintWrapper);
                analysis.doAnalysis();
                sinks.addAll(analysis.getSinks());
                changed |= analysis.isChanged();
            }
        }

        iter++;
    }
}
```

获取所有的类的方法体，然后对其进行数据流分析。soot提供了三种实现，对于污点分析，使用ForwardFlowAnalysis。使用soot框架的来进行数据流分析，只需要（往往在构造器函数中）调用：

- super(DirectedGraph(g))
- super.doAnalysis()

即可开始进行数据流分析，但**前提**是重写给定的若干种方法：mergy、copy、entryInitialFlow、newInitialFlow、flowThrough。

其中flowThrough是核心部分，主要处理进行 kill 和 gen 处理。

```java
public class TaintFlowAnalysis extends ForwardFlowAnalysis<Unit, Set<Taint>> {
    
    private static final CallGraph cg = Scene.v().hasCallGraph() ? Scene.v().getCallGraph() : null;
    
    @Override
    protected void flowThrough(Set<Taint> in, Unit unit, Set<Taint> out) {
        Stmt stmt = (Stmt) unit;

        if (stmt instanceof AssignStmt) {
            visitAssign(in, (AssignStmt) stmt, out);
        }

        if (stmt instanceof InvokeStmt) {
            InvokeExpr invoke = stmt.getInvokeExpr();
            if (!sourceSinkManager.isSource(stmt)) {
                visitInvoke(in, stmt, invoke, out);
            }
        }

        if (stmt instanceof ReturnStmt || stmt instanceof ReturnVoidStmt) {
            visitReturn(in, stmt);
        }

        if (sourceSinkManager.isSink(stmt)) {
            visitSink(in, stmt);
        }
    }
}
```

根据语句的不同类型，进行具体的处理，以 InvokeStmt 调用语句为例：

```java
 private void visitInvoke(Set<Taint> in, Stmt stmt, InvokeExpr invoke, Set<Taint> out) {
 	// kill and gen的具体实现，#todo
 }
```

### Result

`result.keyset().size()`：

输出格式如下：

```json
{
    "hadoop.registry.dns.split-reverse-zone": [
        {
            "taint": "source",
            "methodName": "initializeReverseLookupZone",
            "className": "org.apache.hadoop.registry.server.dns.RegistryDNS",
            "lineNumber": "412"
        }
    ],
    "hadoop.security.group.mapping.ldap.directory.search.timeout": [
        {
            "taint": "sink",
            "methodName": "setConf",
            "className": "org.apache.hadoop.security.LdapGroupsMapping",
            "lineNumber": "757"
        },
        {
            "taint": "sink",
            "methodName": "setConf",
            "className": "org.apache.hadoop.security.LdapGroupsMapping",
            "lineNumber": "759"
        },
        {
            "taint": "source",
            "methodName": "setConf",
            "className": "org.apache.hadoop.security.LdapGroupsMapping",
            "lineNumber": "757"
        }
    ],
}
```

以`hadoop.security.group.mapping.ldap.directory.search.timeout`为例：

其`source`在类`org.org.apache.hadoop.security.LdapGroupsMapping`的`setConf`方法，该方法在`757`行。

![image-20220926162217929](https://happytsing-figure-bed.oss-cn-hangzhou.aliyuncs.com/xt/image-20220926162217929.png)

此后经过一定顺序的传播，其中经过了上述两个`sink`（此处无法看出顺序）。

代码实现：

```java
// 新的输出结果
if (printResults) {
    logger.info("Printing results...");
    Map<String,Set<Map<String,String>>> result = new HashMap<>();
    logger.error("sources sizes = {}",sources.size());
    for (Taint source : sources) {
        List<List<Taint>> paths = pathsMap.get(source);
        String conf = getConf(source);
        genResult(result,conf,source,"source");
        for (List<Taint> path : paths) {
            for (Taint t : path) {
                if (t.getStmt() instanceof PhantomIdentityStmt ||
                    t.getStmt() instanceof PhantomRetStmt)
                    continue;
                genResult(result,conf,t,"sink");
            }
        }
    }
    String jsonResult = JSON.toJSONString(result);
    try {
        BufferedWriter out = new BufferedWriter(new FileWriter("cflow_result_wlq.json"));
        out.write(jsonResult);
        out.close();
    } catch (IOException e) {
        throw new RuntimeException(e);
    }
    logger.info("size of result: {}",String.valueOf(result.keySet().size()));

}

/**
 * 从source的stmt中获取配置的名字，如"fs.getspaceused.jitterMillis"
 * @param source 污染源
 * @return 配置名conf
 */
private String getConf(Taint source){
    String conf;
    Stmt stmt  = source.getStmt();
    assert stmt.containsInvokeExpr();
    List<Value> args = stmt.getInvokeExpr().getArgs();
    conf = args.get(0).toString().replace("\"","");
    return conf;
}

/**
 * 生成result
 * @param result 新的cflow结果
 * @param conf   配置名
 * @param target 需要加入result的污点
 * @param type   类型：source or sink
 */
private void genResult(Map<String,Set<Map<String,String>>> result,String conf, Taint target, String type){
    Map<String,String> map = new HashMap<>();
    String _className = target.getMethod().getDeclaringClass().getName();
    String _methodName = target.getMethod().getName();
    String _lineNumer = String.valueOf(target.getStmt().getJavaSourceStartLineNumber());
    map.put("className",_className);
    map.put("methodName",_methodName);
    map.put("lineNumber",_lineNumer);
    map.put("taint",type);
    if(result.containsKey(conf)){
        result.get(conf).add(map);
        logger.info("Existed conf: {}",conf);
    }else {
        Set<Map<String,String>> set = new HashSet<>();
        set.add(map);
        result.put(conf,set);
    }
}
```

## 其他

- 支持其他软件
- 可以将cFlow作为库使用
