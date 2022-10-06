package taintAnalysis;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.G;
import soot.PackManager;
import soot.Transform;
import taintAnalysis.sourceSinkManager.ISourceSinkManager;
import taintAnalysis.taintWrapper.ITaintWrapper;

import java.util.List;
import java.util.Properties;

public class TaintAnalysisDriver {

    private final static Logger logger = LoggerFactory.getLogger(TaintAnalysisDriver.class);

    private ISourceSinkManager sourceSinkManager;
    private ITaintWrapper taintWrapper;

    public TaintAnalysisDriver(ISourceSinkManager sourceSinkManager) {
        this(sourceSinkManager, null);
    }

    public TaintAnalysisDriver(ISourceSinkManager sourceSinkManager, ITaintWrapper taintWrapper) {
        this.sourceSinkManager = sourceSinkManager;
        this.taintWrapper = taintWrapper;
    }

    public IntraAnalysisTransformer runIntraTaintAnalysis(List<String> srcPaths, List<String> classPaths) {
        G.reset();

        String classPath;
        Properties props = System.getProperties();
        String os = props.getProperty("os.name");
        if(os.toLowerCase().contains("windows")){
            classPath = String.join(";",classPaths);
        }else{
            classPath = String.join(":", classPaths);
        }
        String[] initArgs = {
                // Input Options
                "-cp", classPath,
                "-pp",
                "-allow-phantom-refs",
                "-no-bodies-for-excluded",

                // Output Options
                "-f", "J",
        };

        String[] sootArgs = new String[initArgs.length + 2 * srcPaths.size()];
        for (int i = 0; i < initArgs.length; i++) {
            sootArgs[i] = initArgs[i];
        }
        for (int i = 0; i < srcPaths.size(); i++) {
            sootArgs[initArgs.length + 2*i] = "-process-dir";
            sootArgs[initArgs.length + 2*i + 1] = srcPaths.get(i);
        }

        PackManager.v().getPack("jtp").add(
                new Transform("jtp.taintanalysis", new IntraAnalysisTransformer(sourceSinkManager, taintWrapper)));

        logger.info("sootArgs:{}",sootArgs);
        soot.Main.main(sootArgs);

        IntraAnalysisTransformer transformer = (IntraAnalysisTransformer)
                PackManager.v().getPack("jtp").get("jtp.taintanalysis").getTransformer();
        return transformer;
    }

    public InterAnalysisTransformer runInterTaintAnalysis(List<String> srcPaths, List<String> classPaths, boolean use_spark) {
        G.reset();
        String classPath;
        Properties props = System.getProperties();
        String os = props.getProperty("os.name");
        // soot 中 windows 系统需要使用分号进行分隔
        if(os.toLowerCase().contains("windows")){
             classPath = String.join(";",classPaths);
        }else{
             classPath = String.join(":", classPaths);
        }
        String[] initArgs;
        if (use_spark) {
            logger.info("use spark inter-...!!!");
            initArgs = new String[]{
                    // General Options
                    "-w",

                    // Input Options
                    "-cp", classPath,
                    "-pp",
                    "-allow-phantom-refs",
                    "-no-bodies-for-excluded",
                    "-keep-line-number",

                    // Output Options
                    "-f", "J",

                    // Phase Options
                    "-p", "cg", "all-reachable",
                    "-p", "cg.spark", "enabled",
                    "-p", "cg.spark", "apponly"
            };
        } else {
            initArgs = new String[]{
                    // General Options
                    "-w",

                    // Input Options
                    "-cp", classPath,
                    "-pp",
                    "-allow-phantom-refs",
                    "-no-bodies-for-excluded",

                    // Output Options
                    "-f", "J",

                    // Phase Options
                    "-p", "cg", "off"
            };
        }
        logger.debug("initArgs.length: {}",String.valueOf(initArgs.length)); // 11
        logger.debug("srcPaths.size: {}",srcPaths.size());                   // 4

        // 初始化了一个长度为 11 + 2*4 = 19 的string数组
        String[] sootArgs = new String[initArgs.length + 2 * srcPaths.size()];
//        for(String s:sootArgs){
//            logger.debug(s);
//        }

        // 赋值
        for (int i = 0; i < initArgs.length; i++) {
            sootArgs[i] = initArgs[i];
        }
//        for(String s:sootArgs){
//            logger.debug(s);
//        }

        /** 使用 –process-dir选项使用 Soot 处理整个目录或 JAR 文件
         *  此处还是在添加内容到sootArgs中
         */

        for (int i = 0; i < srcPaths.size(); i++) {
            sootArgs[initArgs.length + 2*i] = "-process-dir";
            sootArgs[initArgs.length + 2*i + 1] = srcPaths.get(i);
        }
//        for(String s:sootArgs){
//            logger.debug(s);
//        }

        PackManager.v().getPack("wjtp").add(
                new Transform("wjtp.taintanalysis", new InterAnalysisTransformer(sourceSinkManager, taintWrapper)));

        soot.Main.main(sootArgs);

        InterAnalysisTransformer transformer = (InterAnalysisTransformer)
                PackManager.v().getPack("wjtp").get("wjtp.taintanalysis").getTransformer();
        return  transformer;
    }

    public ISourceSinkManager getSourceSinkManager() {
        return sourceSinkManager;
    }

    public void setSourceSinkManager(ISourceSinkManager sourceSinkManager) {
        this.sourceSinkManager = sourceSinkManager;
    }

    public ITaintWrapper getTaintWrapper() {
        return taintWrapper;
    }

    public void setTaintWrapper(ITaintWrapper taintWrapper) {
        this.taintWrapper = taintWrapper;
    }

}
