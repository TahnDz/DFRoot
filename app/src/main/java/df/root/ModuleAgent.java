package df.root;

import android.content.Context;
import android.net.Uri;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Client side of the DFRoot root agent.
 *
 * The agent (see jni/agent.c) runs as uid 0 and watches {@link #JOBS_DIR} for
 * request files.  A request is a plain "key=value" text file; the answer is
 * written next to it as "<id>.out" using the same format.
 */
public class ModuleAgent {

    private static final String TAG = "dfroot";

    public static final String ROOT_DIR    = "/data/user_de/0/df.root";
    public static final String JOBS_DIR    = ROOT_DIR + "/jobs";
    public static final String STAGING_DIR = ROOT_DIR + "/staging";
    public static final String BOOTSTRAP   = ROOT_DIR + "/bootstrap";

    /** A module as reported by the agent. */
    public static class ModuleInfo {
        public String id = "";
        public String name = "";
        public String version = "";
        public boolean loaded;

        @Override
        public String toString() {
            return id + " (" + name + " v" + version + (loaded ? ", loaded" : "") + ")";
        }
    }

    /** Result of a job. */
    public static class Result {
        public boolean ok;
        public String message = "";
        public final List<ModuleInfo> modules = new ArrayList<>();

        public ModuleInfo find(String id) {
            for (ModuleInfo m : modules)
                if (m.id.equals(id)) return m;
            return null;
        }
    }

    private static File ensureDir(File dir) {
        if (!dir.exists()) dir.mkdirs();
        dir.setReadable(true, false);
        dir.setWritable(true, false);
        dir.setExecutable(true, false);
        return dir;
    }

    /** True when the root agent is up and answering. */
    public static boolean isAgentAlive() {
        return new File(JOBS_DIR, "agent.pid").exists();
    }

    /** Copy a user picked .ko into the staging area the agent can read. */
    public static File stageKo(Context ctx, Uri uri, String moduleId) throws IOException {
        File dir = ensureDir(new File(STAGING_DIR));
        File dst = new File(dir, moduleId + ".ko");
        try (InputStream in = ctx.getContentResolver().openInputStream(uri);
             OutputStream out = new FileOutputStream(dst)) {
            if (in == null) throw new IOException("cannot open " + uri);
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }
        dst.setReadable(true, false);
        dst.setWritable(true, false);
        return dst;
    }

    private static String escape(String v) {
        return v.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "");
    }

    /** Send a job to the agent and wait for its answer. */
    public static Result submit(Context ctx, Map<String, String> params, long timeoutMs) {
        Result res = new Result();
        File jobs = ensureDir(new File(JOBS_DIR));
        ensureDir(new File(STAGING_DIR));

        String id = "job-" + System.currentTimeMillis() + "-"
                + Math.abs(new Random().nextInt(1000000));
        File jobFile = new File(jobs, id + ".job");
        File tmpFile = new File(jobs, id + ".tmp");
        File outFile = new File(jobs, id + ".out");

        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : params.entrySet())
            sb.append(e.getKey()).append('=').append(escape(e.getValue())).append('\n');

        try (OutputStream os = new FileOutputStream(tmpFile)) {
            os.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            res.message = "cannot write job: " + e.getMessage();
            return res;
        }
        // rename is atomic: the agent never sees a half written job
        if (!tmpFile.renameTo(jobFile)) {
            res.message = "cannot submit job to the root agent";
            tmpFile.delete();
            return res;
        }

        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (outFile.exists()) {
                parse(outFile, res);
                outFile.delete();
                jobFile.delete();
                return res;
            }
            try {
                Thread.sleep(150);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        outFile.delete();
        jobFile.delete();
        res.ok = false;
        res.message = "root agent did not answer - run the root exploit first";
        return res;
    }

    private static void parse(File outFile, Result res) {
        String content;
        try (InputStream in = new FileInputStream(outFile)) {
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            content = new String(bos.toByteArray(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            res.message = "cannot read result: " + e.getMessage();
            return;
        }
        for (String line : content.split("\n")) {
            if (line.startsWith("status=")) {
                res.ok = "ok".equals(line.substring(7).trim());
            } else if (line.startsWith("message=")) {
                res.message = line.substring(8).trim();
            } else if (line.startsWith("mod=")) {
                String[] parts = line.substring(4).split("\\|", -1);
                ModuleInfo m = new ModuleInfo();
                m.id = parts.length > 0 ? parts[0] : "";
                m.name = parts.length > 1 ? parts[1] : m.id;
                m.version = parts.length > 2 ? parts[2] : "";
                m.loaded = parts.length > 3 && "loaded".equals(parts[3]);
                res.modules.add(m);
            }
        }
    }

    /**
     * Best effort: (re)start the agent through the SU manager's su binary.
     * Used when the device rebooted and DFRoot has not run the exploit yet.
     */
    public static boolean startAgentViaSu() {
        String[] candidates = {"/system/bin/su", "/system/xbin/su", "/debug_ramdisk/su", "su"};
        String[] commands = {
                "setsid " + BOOTSTRAP + " --agent >/dev/null 2>&1 &",
                BOOTSTRAP + " --agent >/dev/null 2>&1 &"
        };
        for (String su : candidates) {
            for (String cmd : commands) {
                try {
                    ProcessBuilder pb = new ProcessBuilder(su, "-c", cmd);
                    pb.redirectErrorStream(true);
                    Process p = pb.start();
                    p.getOutputStream().close();
                    Thread waiter = new Thread(() -> {
                        try { p.waitFor(); } catch (InterruptedException ignored) {}
                    });
                    waiter.start();
                    waiter.join(4000);
                    if (isAgentAlive()) {
                        Log.i(TAG, "agent started via " + su);
                        return true;
                    }
                } catch (Exception e) {
                    Log.w(TAG, "cannot start agent via " + su + ": " + e);
                }
            }
        }
        return false;
    }

    /** Convenience: list the modules known to the agent. */
    public static Result list(Context ctx) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("op", "list");
        return submit(ctx, params, 15000);
    }
}
