package df.root;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Flashes custom kernel modules (.ko) into the SU manager module directory
 * (/data/adb/modules) so they show up in KernelSU / KernelSU-Next and can be
 * re-flashed (updated) at any time.
 */
public class ModuleActivity extends Activity {

    private static final int REQ_PICK_KO = 1001;

    private TextView tvAgentState;
    private TextView tvKoPath;
    private TextView tvStatus;
    private EditText etModuleId;
    private EditText etModuleName;
    private EditText etModuleVersion;
    private CheckBox cbLoadNow;
    private ListView lvModules;

    private final List<ModuleAgent.ModuleInfo> modules = new ArrayList<>();
    private ModuleAdapter adapter;

    private final ExecutorService exec = Executors.newSingleThreadExecutor();
    private String stagedKoPath;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_module);
        getActionBar().setTitle("Module Flasher");
        getActionBar().setSubtitle("@diabl0w github/xda");

        tvAgentState = findViewById(R.id.tvAgentState);
        tvKoPath = findViewById(R.id.tvKoPath);
        tvStatus = findViewById(R.id.tvStatus);
        etModuleId = findViewById(R.id.etModuleId);
        etModuleName = findViewById(R.id.etModuleName);
        etModuleVersion = findViewById(R.id.etModuleVersion);
        cbLoadNow = findViewById(R.id.cbLoadNow);
        lvModules = findViewById(R.id.lvModules);

        Button btnPick = findViewById(R.id.btnPickKo);
        Button btnFlash = findViewById(R.id.btnFlash);
        Button btnRefresh = findViewById(R.id.btnRefresh);
        Button btnRemove = findViewById(R.id.btnRemove);

        btnPick.setOnClickListener(v -> pickKo());
        btnFlash.setOnClickListener(v -> flash());
        btnRefresh.setOnClickListener(v -> refresh());
        btnRemove.setOnClickListener(v -> confirmRemove());

        adapter = new ModuleAdapter();
        lvModules.setAdapter(adapter);
        lvModules.setOnItemClickListener((parent, view, pos, id) -> {
            ModuleAgent.ModuleInfo m = modules.get(pos);
            etModuleId.setText(m.id);
            etModuleName.setText(m.name);
            tvStatus.setText("Selected " + m.id + " - pick a .ko and flash to re-flash it");
        });
        lvModules.setOnItemLongClickListener((AdapterView.OnItemLongClickListener)
                (parent, view, pos, id) -> {
                    confirmRemove(modules.get(pos).id);
                    return true;
                });

        updateAgentState();
        refresh();
    }

    @Override
    protected void onDestroy() {
        exec.shutdownNow();
        super.onDestroy();
    }

    private void updateAgentState() {
        boolean alive = ModuleAgent.isAgentAlive();
        tvAgentState.setText(alive
                ? "Root agent: running"
                : "Root agent: not running - run the root exploit (or grant root to DFRoot) first");
    }

    /* ------------------------------------------------------------- picker */

    private void pickKo() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{"application/octet-stream", "*/*"});
        try {
            startActivityForResult(i, REQ_PICK_KO);
        } catch (Exception e) {
            tvStatus.setText("No file picker available: " + e.getMessage());
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_PICK_KO || resultCode != RESULT_OK || data == null)
            return;
        Uri uri = data.getData();
        if (uri == null) return;

        final String name = queryDisplayName(uri);
        final String guessId = sanitizeId(name);
        tvStatus.setText("Copying " + name + " ...");
        exec.execute(() -> {
            String error = null;
            File staged = null;
            try {
                staged = ModuleAgent.stageKo(this, uri, guessId);
            } catch (Exception e) {
                error = String.valueOf(e.getMessage());
            }
            final File f = staged;
            final String err = error;
            runOnUiThread(() -> {
                if (err != null) {
                    tvStatus.setText("Copy failed: " + err);
                    return;
                }
                stagedKoPath = f.getAbsolutePath();
                tvKoPath.setText("File: " + f.getName() + " (" + f.length() + " bytes)");
                if (etModuleId.getText().length() == 0) etModuleId.setText(guessId);
                if (etModuleName.getText().length() == 0) etModuleName.setText(guessId);
                tvStatus.setText("Ready to flash");
            });
        });
    }

    private String queryDisplayName(Uri uri) {
        String name = null;
        try (android.database.Cursor c = getContentResolver().query(uri, null, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx >= 0) name = c.getString(idx);
            }
        } catch (Exception ignored) {}
        if (name == null || name.isEmpty()) name = uri.getLastPathSegment();
        if (name == null || name.isEmpty()) name = "custom_module.ko";
        return name;
    }

    private static String sanitizeId(String raw) {
        String s = raw == null ? "" : raw.trim().toLowerCase(Locale.US);
        if (s.endsWith(".ko")) s = s.substring(0, s.length() - 3);
        s = s.replaceAll("[^a-z0-9._-]", "_");
        while (s.startsWith(".")) s = s.substring(1);
        if (s.isEmpty()) s = "custom_module";
        return s;
    }

    /* -------------------------------------------------------------- flash */

    private void flash() {
        final String id = sanitizeId(etModuleId.getText().toString());
        final String name = etModuleName.getText().toString().trim();
        final String version = etModuleVersion.getText().toString().trim();
        final boolean loadNow = cbLoadNow.isChecked();

        if (stagedKoPath == null) {
            tvStatus.setText("Select a .ko file first");
            return;
        }

        final boolean exists = ModuleAgent.isAgentAlive();
        tvStatus.setText("Flashing " + id + " ...");
        exec.execute(() -> {
            ModuleAgent.Result res = null;
            if (!ModuleAgent.isAgentAlive()) {
                // try to (re)start the agent through the SU manager
                ModuleAgent.startAgentViaSu();
            }
            Map<String, String> params = new LinkedHashMap<>();
            params.put("op", "flash");
            params.put("id", id);
            params.put("name", name.isEmpty() ? id : name);
            params.put("version", version.isEmpty() ? "1.0" : version);
            params.put("versionCode", "1");
            params.put("author", "DFRoot");
            params.put("description", "Custom module flashed by DFRoot");
            params.put("ko", stagedKoPath);
            params.put("load_now", loadNow ? "1" : "0");
            res = ModuleAgent.submit(this, params, 30000);
            final ModuleAgent.Result result = res;
            final boolean agentWasAlive = exists;
            runOnUiThread(() -> {
                tvStatus.setText(result.message.isEmpty()
                        ? (result.ok ? "Done" : "Failed")
                        : result.message);
                if (!result.ok) {
                    Toast.makeText(this, result.message, Toast.LENGTH_LONG).show();
                }
                updateAgentState();
                refresh();
            });
            if (!agentWasAlive) updateAgentState();
        });
    }

    private void confirmRemove() {
        confirmRemove(sanitizeId(etModuleId.getText().toString()));
    }

    private void confirmRemove(String id) {
        if (id.isEmpty()) {
            tvStatus.setText("Select a module first");
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Remove module")
                .setMessage("Remove " + id + " from " + "/data/adb/modules" + "?")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Remove", (d, w) -> removeModule(id))
                .show();
    }

    private void removeModule(String id) {
        tvStatus.setText("Removing " + id + " ...");
        exec.execute(() -> {
            Map<String, String> params = new LinkedHashMap<>();
            params.put("op", "uninstall");
            params.put("id", id);
            ModuleAgent.Result res = ModuleAgent.submit(this, params, 30000);
            runOnUiThread(() -> {
                tvStatus.setText(res.message.isEmpty() ? (res.ok ? "Removed" : "Failed") : res.message);
                refresh();
            });
        });
    }

    /* --------------------------------------------------------------- list */

    private void refresh() {
        if (!ModuleAgent.isAgentAlive()) {
            modules.clear();
            adapter.notifyDataSetChanged();
            updateAgentState();
            return;
        }
        exec.execute(() -> {
            ModuleAgent.Result res = ModuleAgent.list(this);
            runOnUiThread(() -> {
                modules.clear();
                modules.addAll(res.modules);
                adapter.notifyDataSetChanged();
                if (!res.ok && tvStatus.getText().length() == 0)
                    tvStatus.setText(res.message);
                updateAgentState();
            });
        });
    }

    /* ------------------------------------------------------------ adapter */

    private class ModuleAdapter extends BaseAdapter {
        @Override
        public int getCount() {
            return modules.size();
        }

        @Override
        public ModuleAgent.ModuleInfo getItem(int pos) {
            return modules.get(pos);
        }

        @Override
        public long getItemId(int pos) {
            return pos;
        }

        @Override
        public View getView(int pos, View v, ViewGroup parent) {
            View view = v;
            if (view == null)
                view = LayoutInflater.from(ModuleActivity.this)
                        .inflate(R.layout.item_module, parent, false);
            ModuleAgent.ModuleInfo m = modules.get(pos);
            ((TextView) view.findViewById(R.id.tvModuleId)).setText(m.id);
            ((TextView) view.findViewById(R.id.tvModuleInfo)).setText(
                    m.name + "  -  v" + m.version + (m.loaded ? "  (loaded)" : ""));
            return view;
        }
    }
}
