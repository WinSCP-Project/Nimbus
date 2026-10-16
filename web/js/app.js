const $ = (id) => document.getElementById(id);

let state = {
  settings: {},
  subscriptions: [],
  nodes: [],
  selected_node_id: "",
  connected: false,
  connecting: false,
  core_version: "",
  uplink: 0,
  downlink: 0,
  last_error: "",
};
let activeSub = "all";
let busy = false;

const api = (path, opts = {}) =>
  fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  }).then(async (r) => {
    const text = await r.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch { data = { error: text }; }
    if (!r.ok) throw new Error(data.error || r.statusText);
    return data;
  });

function toast(msg, err) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.toggle("err", !!err);
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 3200);
}

function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function quota(sub) {
  if (!sub.total) return `${(sub.nodes || 0)} узлов`;
  const used = (sub.upload || 0) + (sub.download || 0);
  return `${fmtBytes(used)} / ${fmtBytes(sub.total)}`;
}

function latencyClass(ms) {
  if (!ms) return { t: "—", c: "na" };
  if (ms < 0) return { t: "fail", c: "bad" };
  if (ms < 180) return { t: ms + " ms", c: "ok" };
  if (ms < 450) return { t: ms + " ms", c: "mid" };
  return { t: ms + " ms", c: "bad" };
}

function selectedNode() {
  return state.nodes.find((n) => n.id === state.selected_node_id) || null;
}

function filteredNodes() {
  const q = ($("search").value || "").toLowerCase();
  const proto = $("proto-filter").value;
  return state.nodes.filter((n) => {
    if (activeSub !== "all" && n.sub_id !== activeSub) return false;
    if (proto && n.protocol !== proto) return false;
    if (q && !(`${n.name} ${n.server} ${n.protocol}`.toLowerCase().includes(q))) return false;
    return true;
  });
}

function render() {
  const counts = {};
  for (const n of state.nodes) counts[n.sub_id] = (counts[n.sub_id] || 0) + 1;

  $("sub-list").innerHTML = [
    `<div class="sub-item ${activeSub === "all" ? "active" : ""}" data-id="all">
       <div><div class="name">Все узлы</div><div class="meta">${state.nodes.length} шт.</div></div>
     </div>`,
    ...state.subscriptions.map((s) => `
      <div class="sub-item ${activeSub === s.id ? "active" : ""}" data-id="${s.id}">
        <div>
          <div class="name">${esc(s.name)}</div>
          <div class="meta">${counts[s.id] || 0} · ${s.last_error ? "ошибка" : quota({ ...s, nodes: counts[s.id] })}</div>
        </div>
        <button class="x" data-del="${s.id}" title="Удалить">×</button>
      </div>`),
  ].join("");

  const nodes = filteredNodes();
  $("empty").classList.toggle("hidden", nodes.length > 0);
  $("node-body").innerHTML = nodes.map((n) => {
    const lat = latencyClass(n.latency_ms);
    const on = state.selected_node_id === n.id;
    return `<tr data-id="${n.id}" class="${on ? "selected" : ""}">
      <td><span class="dot ${on && state.connected ? "on" : ""}"></span></td>
      <td>${esc(n.name)}</td>
      <td><span class="proto ${esc(n.protocol)}">${esc(n.protocol)}</span></td>
      <td>${esc(n.server)}:${n.port}</td>
      <td class="lat ${lat.c}">${lat.t}</td>
    </tr>`;
  }).join("");

  const n = selectedNode();
  $("orb").classList.toggle("live", state.connected);
  $("conn-title").textContent = state.connecting ? "Подключение…" : state.connected ? "Подключено" : "Не подключено";
  $("conn-sub").textContent = n
    ? `${n.name} · ${n.server}:${n.port}`
    : "выбери узел и нажми Подключить";
  $("up").textContent = fmtBytes(state.uplink);
  $("down").textContent = fmtBytes(state.downlink);
  $("mode-label").textContent = state.settings.mode || "rule";
  const btn = $("btn-toggle");
  btn.textContent = state.connected ? "Отключить" : "Подключить";
  btn.classList.toggle("on", state.connected);
  $("core-pill").textContent = state.core_version ? state.core_version : "ядро не загружено";
  if (state.last_error && !state.connected) {
    $("conn-sub").textContent = state.last_error;
  }
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function applyState(next) {
  state = {
    ...state,
    ...next,
    subscriptions: next.subscriptions || [],
    nodes: next.nodes || [],
    settings: next.settings || state.settings || {},
  };
  render();
}

async function refresh() {
  const s = await api("/api/state");
  applyState(s);
}

function openModal(id) { $(id).classList.remove("hidden"); }
function closeModal(id) { $(id).classList.add("hidden"); }

$("btn-add-sub").onclick = () => openModal("modal-sub");
$("btn-import").onclick = () => openModal("modal-import");
$("btn-settings").onclick = async () => {
  fillSettings();
  try {
    const logs = await api("/api/logs");
    $("log-view").textContent = (logs.lines || []).join("\n");
  } catch {}
  openModal("modal-settings");
};
$("btn-update-all").onclick = async () => {
  try {
    for (const s of state.subscriptions) {
      if (s.manual || !s.url) continue;
      await api(`/api/subscriptions/${s.id}/update`, { method: "POST", body: "{}" });
    }
    await refresh();
    toast("Подписки обновлены");
  } catch (e) { toast(e.message, true); }
};

document.querySelectorAll("[data-close]").forEach((b) => {
  b.onclick = () => closeModal(b.getAttribute("data-close"));
});

$("sub-save").onclick = async () => {
  try {
    await api("/api/subscriptions", {
      method: "POST",
      body: JSON.stringify({
        name: $("sub-name").value,
        url: $("sub-url").value,
        user_agent: $("sub-ua").value,
      }),
    });
    $("sub-name").value = "";
    $("sub-url").value = "";
    closeModal("modal-sub");
    await refresh();
    toast("Подписка добавлена");
  } catch (e) { toast(e.message, true); }
};

$("import-save").onclick = async () => {
  try {
    const res = await api("/api/import", {
      method: "POST",
      body: JSON.stringify({
        sub_id: activeSub === "all" ? "" : activeSub,
        text: $("import-text").value,
      }),
    });
    $("import-text").value = "";
    closeModal("modal-import");
    await refresh();
    toast("Импортировано: " + res.imported);
  } catch (e) { toast(e.message, true); }
};

function fillSettings() {
  const s = state.settings || {};
  $("set-mode").value = s.mode || "rule";
  $("set-port").value = s.mixed_port || 10808;
  $("set-clash").value = s.clash_api_port || 9090;
  $("set-log").value = s.log_level || "info";
  $("set-rdns").value = s.remote_dns || "";
  $("set-ddns").value = s.direct_dns || "";
  $("set-au").value = s.auto_update_h ?? 6;
  $("set-ping").value = s.ping_timeout_ms || 4000;
  $("set-exclude").value = s.exclude || "";
  $("set-include").value = s.include || "";
  $("set-lan").checked = !!s.bind_lan;
  $("set-tun").checked = !!s.tun;
  $("set-insecure").checked = !!s.allow_insecure;
  $("set-mux").checked = !!s.mux;
}

$("set-save").onclick = async () => {
  const next = {
    ...state.settings,
    mode: $("set-mode").value,
    mixed_port: Number($("set-port").value),
    clash_api_port: Number($("set-clash").value),
    log_level: $("set-log").value,
    remote_dns: $("set-rdns").value,
    direct_dns: $("set-ddns").value,
    auto_update_h: Number($("set-au").value),
    ping_timeout_ms: Number($("set-ping").value),
    exclude: $("set-exclude").value,
    include: $("set-include").value,
    bind_lan: $("set-lan").checked,
    tun: $("set-tun").checked,
    allow_insecure: $("set-insecure").checked,
    mux: $("set-mux").checked,
  };
  try {
    await api("/api/settings", { method: "PUT", body: JSON.stringify(next) });
    await refresh();
    closeModal("modal-settings");
    toast("Настройки сохранены");
  } catch (e) { toast(e.message, true); }
};

$("sub-list").onclick = async (e) => {
  const del = e.target.closest("[data-del]");
  if (del) {
    e.stopPropagation();
    if (!confirm("Удалить подписку и её узлы?")) return;
    try {
      await api(`/api/subscriptions/${del.getAttribute("data-del")}`, { method: "DELETE" });
      activeSub = "all";
      await refresh();
    } catch (err) { toast(err.message, true); }
    return;
  }
  const item = e.target.closest(".sub-item");
  if (!item) return;
  activeSub = item.getAttribute("data-id");
  render();
};

$("node-body").onclick = async (e) => {
  const tr = e.target.closest("tr");
  if (!tr) return;
  const id = tr.getAttribute("data-id");
  try {
    await api("/api/nodes/select", { method: "POST", body: JSON.stringify({ id }) });
    state.selected_node_id = id;
    render();
  } catch (err) { toast(err.message, true); }
};

$("node-body").ondblclick = () => $("btn-toggle").click();

$("btn-toggle").onclick = async () => {
  if (busy) return;
  busy = true;
  try {
    if (state.connected) {
      applyState(await api("/api/disconnect", { method: "POST", body: "{}" }));
    } else {
      if (!state.selected_node_id) {
        toast("Сначала выбери узел", true);
        return;
      }
      applyState(await api("/api/connect", { method: "POST", body: JSON.stringify({ id: state.selected_node_id }) }));
    }
  } catch (e) { toast(e.message, true); await refresh(); }
  finally { busy = false; }
};

$("btn-ping").onclick = async () => {
  try {
    toast("Пинг…");
    await api("/api/ping-all", { method: "POST", body: "{}" });
    await refresh();
  } catch (e) { toast(e.message, true); }
};

$("search").oninput = render;
$("proto-filter").onchange = render;

function bindSSE() {
  try {
    const es = new EventSource("/api/events");
    es.onmessage = (ev) => {
      try { applyState(JSON.parse(ev.data)); } catch {}
    };
  } catch {
    setInterval(() => refresh().catch(() => {}), 2000);
  }
}

refresh().then(bindSSE).catch((e) => toast(e.message, true));
