package taintAnalysis;

import com.alibaba.fastjson.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.SceneTransformer;
import soot.SootMethod;
import soot.Value;
import soot.jimple.Stmt;
import taintAnalysis.sourceSinkManager.ISourceSinkManager;
import taintAnalysis.taintWrapper.ITaintWrapper;
import taintAnalysis.utility.PhantomIdentityStmt;
import taintAnalysis.utility.PhantomRetStmt;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class InterAnalysisTransformer extends SceneTransformer {

    private final static Logger logger = LoggerFactory.getLogger(InterAnalysisTransformer.class);

    private final InterTaintAnalysis analysis;
    private boolean printResults = true;
    private Map<Taint, List<List<Taint>>> pathsMap = new HashMap<>();

    public InterAnalysisTransformer(ISourceSinkManager sourceSinkManager, ITaintWrapper taintWrapper) {
        this.analysis = new InterTaintAnalysis(sourceSinkManager, taintWrapper);
    }

    public List<Taint> getSources() {
        return analysis.getSources();
    }

    public Map<SootMethod, Map<Taint, List<Set<Taint>>>> getMethodSummary() {
        return analysis.getMethodSummary();
    }

    public Map<SootMethod, Map<Taint, Taint>> getMethodTaintCache() {
        return analysis.getMethodTaintCache();
    }

    @Override
    protected void internalTransform(String phaseName, Map<String, String> options) {
        analysis.doAnalysis();

        Set<Taint> sinks = new HashSet<>();
        ArrayList<Taint> sources = new ArrayList<>(analysis.getSources());
        sources.sort(Comparator.comparing(Taint::toString));

        // // For validation only
        // PathVisitor pv = new PathVisitor();
        // for (Taint source : sources) {
        //     pv.visit(source);
        // }

        // 此处绘制出 souces 到 sink 的传播路径
       int numOfThread = 5;
       logger.info("Reconstructing path using {} threads...", numOfThread);
       ExecutorService es = Executors.newFixedThreadPool(numOfThread);
       List<SourceSinkConnectionVisitor> todo = new ArrayList<>(sources.size());
       for (Taint source : sources) {
           todo.add(new SourceSinkConnectionVisitor(source));
       }
       try {
           es.invokeAll(todo);
       } catch (InterruptedException e) {
           e.printStackTrace();
       }
       for (SourceSinkConnectionVisitor pv : todo) {
           pathsMap.put(pv.getSource(), pv.getPaths());
           sinks.addAll(pv.getSinks());
       }
       es.shutdown();

       logger.info("Number of sinks reached by path reconstruction: {}", sinks.size());

       // 原本的输出结果
       if (printResults) {
           logger.info("Printing results...");
           for (Taint source : sources) {
               System.out.println("Source: " + source + " reaches:\n");
               List<List<Taint>> paths = pathsMap.get(source);
               for (List<Taint> path : paths) {
                   System.out.println("-- Sink " + path.get(path.size() - 1) + " along:");
                   for (Taint t : path) {
                       if (t.getStmt() instanceof PhantomIdentityStmt ||
                               t.getStmt() instanceof PhantomRetStmt)
                           continue;
                       System.out.println("    -> " + t);
                   }
                   System.out.println();
               }
               System.out.println();
           }
       }

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

       }
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

        }else {
            Set<Map<String,String>> set = new HashSet<>();
            set.add(map);
            result.put(conf,set);
        }
    }
    public Map<Taint, List<List<Taint>>> getPathsMap() {
        return pathsMap;
    }

}
