package taintAnalysis;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import taintAnalysis.sourceSinkManager.ISourceSinkManager;
import taintAnalysis.taintWrapper.ITaintWrapper;

import java.util.*;

public class InterTaintAnalysis {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final ISourceSinkManager sourceSinkManager;
    private final ITaintWrapper taintWrapper;
    private final Set<Taint> sources;
    private final Set<Taint> sinks;
    private final Map<SootMethod, Map<Taint, List<Set<Taint>>>> methodSummary;
    private final Map<SootMethod, Map<Taint, Taint>> methodTaintCache;

    public InterTaintAnalysis(ISourceSinkManager sourceSinkManager, ITaintWrapper taintWrapper) {
        this.sourceSinkManager = sourceSinkManager;
        this.taintWrapper = taintWrapper;
        this.sources = new HashSet<>();
        this.sinks = new HashSet<>();
        this.methodSummary = new HashMap<>();
        this.methodTaintCache = new HashMap<>();
    }

    public void doAnalysis() {
        this.sources.clear();
        this.sinks.clear();
        this.methodSummary.clear();
        this.methodTaintCache.clear();

        List<SootMethod> methodList = new ArrayList<>();
        for (SootClass sc : Scene.v().getApplicationClasses()) {
            for (SootMethod sm : sc.getMethods()) {
                // Returns true if this method is not phantom, abstract or native, i.e.
                // phantom method：是在the process directory 和 the Soot classpath 都不存在的类，但是被其他类调用，于是soot创建该类，其中的方法就是phantom method
                if (sm.isConcrete()) {
                    methodList.add(sm);
                }
            }
        }

        // soot分析，得到了所有的method
        methodList.sort(Comparator.comparing(SootMethod::toString));
        logger.info("method 示例: {}", methodList.get(1));
        logger.info("Num of methods: {}", methodList.size());

        // Bootstrap

        // 第一次 遍历所有body，以及其内部的所有语句stmt，如果是赋值语句，那么判断它是否是污点源sources，并将其加入sources中。
        int iter = 1;
        logger.info("iter {}", iter);
        List<Body> bodyList = new ArrayList<>();
        for (SootMethod sm : methodList) {
            Body b = sm.retrieveActiveBody();
            bodyList.add(b);
        }
        for (Body b : bodyList) {
            TaintFlowAnalysis analysis = new TaintFlowAnalysis(b, sourceSinkManager, Taint.getEmptyTaint(),
                    methodSummary, methodTaintCache, taintWrapper);
            analysis.doAnalysis();
            sources.addAll(analysis.getSources());
        }
        iter++;


        // 之后经过若干次遍历后，污点分析最终趋于稳定，也就是不在change时，结束污点分析。
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

        logger.info("Found {} sinks reached from {} sources", sinks.size(), sources.size());
    }

    public List<Taint> getSources() {
        List<Taint> lst = new ArrayList<>();
        lst.addAll(sources);
        return lst;
    }

    public List<Taint> getSinks() {
        List<Taint> lst = new ArrayList<>();
        lst.addAll(sinks);
        return lst;
    }

    public Map<SootMethod, Map<Taint, List<Set<Taint>>>> getMethodSummary() {
        return methodSummary;
    }

    public Map<SootMethod, Map<Taint, Taint>> getMethodTaintCache() {
        return methodTaintCache;
    }

}
