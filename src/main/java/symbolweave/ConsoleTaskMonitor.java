package symbolweave;

import ghidra.util.task.TaskMonitorAdapter;

final class ConsoleTaskMonitor extends TaskMonitorAdapter {
    private volatile String message = "";
    private long lastRender;

    public void setMessage(String message) {
        this.message = message;
        render();
    }

    public void initialize(long max) {
        super.initialize(max);
        render();
    }

    public void setProgress(long value) {
        super.setProgress(value);
        render();
    }

    public void incrementProgress(long value) {
        super.incrementProgress(value);
        render();
    }

    private synchronized void render() {
        long now = System.currentTimeMillis();
        if (now - lastRender < 5000) return;
        lastRender = now;
        long max = getMaximum(), progress = getProgress();
        System.out.println(
                "Analysis: "
                        + message
                        + (max > 0 && progress >= 0
                                ? String.format(
                                        java.util.Locale.ROOT,
                                        " (%.1f%%)",
                                        Math.min(100.0, 100.0 * progress / max))
                                : ""));
    }
}
