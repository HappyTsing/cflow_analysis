package taintAnalysis;

import configInterface.ConfigInterface;
import soot.Body;
import soot.BodyTransformer;
import soot.Printer;

import java.util.List;
import java.util.Map;

public class IntraTaintAnalysis extends BodyTransformer {

    private ConfigInterface configInterface;

    public IntraTaintAnalysis(ConfigInterface configInterface) {
        this.configInterface = configInterface;
    }

    @Override
    protected void internalTransform(Body b, String phaseName, Map<String, String> options) {
        TaintFlowAnalysis analysis = new TaintFlowAnalysis(b, configInterface);
        analysis.doAnalysis();
        List<Taint> lst = analysis.getSources();
        for (Taint source : lst) {
            System.out.println("source");
            dfs(source, 0);
        }
    }

    private void dfs(Taint t, int depth) {
        for (int i = 0; i < depth; i++) {
            System.out.print("-");
        }
        System.out.println(t);
        for (Taint succ : t.getSuccessors()) {
            dfs(succ, depth + 1);
        }
    }

}
