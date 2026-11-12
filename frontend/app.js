"use strict";

const $ = id => document.getElementById(id);
const pageSize = 150;
const state = {
  mode: "", tab: "packets", text: "", flow: 0, offset: 0, latest: true,
  interval: null, interfaces: [], view: null, selected: 0, detail: null,
  busy: false, dirtyNotes: false, version: 0, theme: "purple", diagnosis: null,
};
let number = new Intl.NumberFormat(localeNames[language]);
const formatNumber = value => number.format(value);
const formatTime = value => value.toFixed(6);
const escape = value => String(value ?? "").replace(/[&<>"']/g, char => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[char]));

let refreshBusy = false;
let refreshPending = false;
let toastTimer;
let detailRequest = 0;
let contentRequest = 0;
let requestContents = null;
let requestPacket = 0;
let tableKey = "";
let sidebarKey = "";
const chartKeys = new Map();

function call(method, ...args) {
  const app = window.go?.main?.App;
  if (!app) return Promise.reject(new Error(t("Модуль захвата LFish недоступен")));
  return app[method](...args);
}

function toast(message, isError = false) {
  const el = $("toast");
  el.textContent = message;
  el.classList.toggle("error", isError);
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, isError ? 10000 : 3500);
}

function showError(error) {
  toast(translateMessage(error?.message ?? String(error)), true);
}

async function run(action) {
  if (state.busy) return;
  state.busy = true;
  updateButtons();
  try {
    await action();
  } catch (error) {
    showError(error);
  } finally {
    state.busy = false;
    updateButtons();
    await refresh();
  }
}

function size(value) {
  if (value >= 1048576) return `${formatNumber(Number((value / 1048576).toFixed(1)))} ${t("МиБ")}`;
  if (value >= 1024) return `${formatNumber(Number((value / 1024).toFixed(1)))} ${t("КиБ")}`;
  return `${formatNumber(value)} ${t("Б")}`;
}

function bytesPerSecond(value, duration) {
  return size(value / duration) + "/" + t("с");
}

function intervalText({from, to}) {
  return `${from}–${to} ${t("с")}`;
}

function basename(path) {
  return path.split("/").at(-1);
}

function changeView() {
  state.version++;
  tableKey = "";
  return refresh();
}

async function refresh() {
  if (!state.mode) return;
  if (refreshBusy) {
    refreshPending = true;
    return;
  }
  refreshBusy = true;
  const version = state.version;
  try {
    const result = await call("View", {
      text: state.text, language, tab: state.tab, flow: state.flow, offset: state.offset,
      latest: state.latest, includeGraph: true,
      hasInterval: !!state.interval, from: state.interval?.from ?? 0, to: state.interval?.to ?? 0,
    });
    if (version === state.version) {
      state.offset = result.offset;
      state.view = result;
      render();
    }
  } catch (error) {
    showError(error);
  } finally {
    refreshBusy = false;
    if (refreshPending) {
      refreshPending = false;
      void refresh();
    }
  }
}

function setMode(mode) {
  state.mode = mode;
  document.body.className = mode;
  updateModeLabels();
  $("workbench").inert = false;
  if ($("welcome").open) $("welcome").close();
  renderDetail();
  return changeView();
}

function updateModeLabels() {
  const mode = state.mode || "advanced";
  $("mode-name").textContent = mode === "simple" ? t("Простой вид") : t("Продвинутый вид");
  $("display").placeholder = mode === "simple" ? t("Поиск по адресу, пакету или заметке") : "tcp || udp || icmp";
}

function applyPreferences(prefs) {
  language = prefs.language;
  state.theme = prefs.theme;
  number = new Intl.NumberFormat(localeNames[language]);
  document.body.dataset.theme = state.theme;
  $("language").value = language;
  $("welcome-language").value = language;
  $("theme").value = state.theme;
  translateStatic();
  updateModeLabels();
  renderInterfaces();
  renderDetail();
  renderDiagnosis();
  tableKey = "";
  sidebarKey = "";
  chartKeys.clear();
  if (state.view) {
    render();
    void changeView();
  }
}

async function savePreferences(prefs, errorId) {
  const controls = [$("language"), $("welcome-language"), $("theme")];
  const errorBox = $(errorId);
  controls.forEach(control => { control.disabled = true; });
  errorBox.hidden = true;
  try {
    await call("SetPreferences", prefs);
    applyPreferences(prefs);
  } catch (error) {
    $("language").value = language;
    $("welcome-language").value = language;
    $("theme").value = state.theme;
    errorBox.textContent = translateMessage(error?.message ?? String(error));
    errorBox.hidden = false;
  } finally {
    controls.forEach(control => { control.disabled = false; });
  }
}

async function loadInterfaces() {
  state.interfaces = (await call("Interfaces")) ?? [];
  renderInterfaces();
}

function renderInterfaces() {
  const before = $("device").value;
  $("device").replaceChildren();
  if (!state.interfaces.length) $("device").append(new Option(t("Нет активных интерфейсов"), ""));
  for (const iface of state.interfaces) {
    const label = iface.loopback ? `${iface.name} · loopback` : iface.name;
    $("device").append(new Option(label, iface.name));
  }
  if (state.interfaces.some(iface => iface.name === before)) $("device").value = before;
  else {
    const preferred = state.interfaces.find(iface => !iface.loopback && iface.addresses?.length);
    if (preferred) $("device").value = preferred.name;
  }
  showAddresses();
  updateButtons();
}

function showAddresses() {
  const iface = state.interfaces.find(item => item.name === $("device").value);
  $("addresses").textContent = iface?.addresses?.join(" · ") ?? "";
}

function updateButtons() {
  const active = state.view?.running ?? false;
  const hasDevice = !!$("device").value;
  for (const id of ["start", "sidebar-start"]) $(id).disabled = active || !hasDevice || state.busy || !state.mode;
  $("stop").disabled = !active || state.busy;
  $("restart").disabled = !hasDevice || state.busy || !state.mode;
  $("device").disabled = active || state.busy;
  $("capture-filter").disabled = active || state.busy;
  $("interfaces").disabled = active || state.busy;
  $("open").disabled = active || state.busy || !state.mode;
  $("save").disabled = !state.view?.stats.total || state.busy;
  $("format").disabled = state.busy;
}

function showScope() {
  const scope = $("scope");
  scope.hidden = !(state.flow || state.interval) || state.tab === "diagnose";
  const parts = [];
  if (state.flow) parts.push(`<span>${t("Соединение #{id}", {id: state.flow})}</span><button class="quiet" data-clear="flow" aria-label="${t("Закрыть соединение")}">×</button>`);
  if (state.interval) parts.push(`<span>${intervalText(state.interval)}</span><button class="quiet" data-clear="interval" aria-label="${t("Сбросить интервал")}">×</button>`);
  scope.innerHTML = parts.join("");
}

function pill(protocol) {
  return `<span class="pill ${escape(protocol.toLowerCase())}">${escape(protocol)}</span>`;
}

function processName(process) {
  if (!process) return "—";
  const pid = `PID ${process.pid}`;
  return process.name ? `${process.name} (${pid})` : pid;
}

function packetRow(packet, showProcess) {
  const mark = packet.marked ? `<span class="mark-star" title="${t("В закладках")}">★</span> ` : "";
  const selected = packet.id === state.selected ? ' class="selected" aria-selected="true"' : "";
  const head = `<tr data-packet="${packet.id}" tabindex="0"${selected}><td>${mark}${packet.id}</td>`;
  const source = escape(packet.source || "—");
  const destination = escape(packet.destination || "—");
  if (state.mode === "simple") {
    const label = state.tab === "notes" ? packet.note || t("Закладка без заметки") : translateMessage(packet.event);
    return head + `<td>${pill(packet.protocol)}</td><td title="${source} → ${destination}">${source} → ${destination}</td><td title="${escape(label)}">${escape(label)}</td></tr>`;
  }
  const label = state.tab === "notes" ? packet.note || t("Закладка без заметки") : packet.info;
  const process = showProcess ? `<td>${escape(processName(packet.process))}</td>` : "";
  return head + `<td>${formatTime(packet.time)}</td><td>${source}</td><td>${destination}</td><td>${pill(packet.protocol)}</td><td>${packet.length}</td>${process}<td title="${escape(label)}">${escape(label)}</td></tr>`;
}

function flowRow(flow) {
  return `<tr data-flow="${flow.id}" tabindex="0"><td>${flow.id}</td><td>${pill(flow.transport)}</td><td>${escape(flow.source)}</td><td>${escape(flow.destination)}</td><td>${formatNumber(flow.count)}</td><td>${size(flow.bytes)} · ${(flow.end - flow.start).toFixed(3)} ${t("с")}</td></tr>`;
}

function renderTable(view) {
  const grouped = state.tab === "flows" && !state.flow;
  const rows = grouped ? view.flows ?? [] : view.packets ?? [];
  const showProcess = state.mode === "advanced" && !!view.interface && !grouped;
  const key = JSON.stringify([state.mode, state.tab, state.flow, state.selected, showProcess, rows]);
  if (key !== tableKey) {
    tableKey = key;
    const notesTab = state.tab === "notes";
    let titles = ["№", "Время, с", "Источник", "Назначение", "Протокол", "Байты", notesTab ? "Заметка" : "Информация"];
    if (showProcess) titles.splice(6, 0, "Процесс");
    if (state.mode === "simple") titles = ["№", "Протокол", "Откуда → куда", notesTab ? "Заметка" : "Событие"];
    if (grouped) titles = ["№", "Протокол", "Откуда", "Куда", "Пакеты", "Объём · длительность"];
    const head = `<tr>${titles.map(title => `<th scope="col">${t(title)}</th>`).join("")}</tr>`;
    if ($("thead").innerHTML !== head) $("thead").innerHTML = head;
    const activeRow = document.activeElement?.closest("#tbody tr");
    const activeId = activeRow?.dataset.packet ?? activeRow?.dataset.flow;
    $("tbody").innerHTML = rows.map(grouped ? flowRow : packet => packetRow(packet, showProcess)).join("");
    if (activeId) $("tbody").querySelector(`[data-${grouped ? "flow" : "packet"}="${activeId}"]`)?.focus({preventScroll: true});
  }

  const empty = $("empty");
  empty.hidden = !!rows.length;
  if (!rows.length) {
    let title = t("Пакетов пока нет");
    let text = view.running ? t("Захват запущен. Ожидаем трафик на интерфейсе.") : t("Выберите интерфейс и начните захват или откройте PCAP-файл.");
    if (noteColumn()) { title = t("Закладок пока нет"); text = t("Выберите пакет и нажмите «Закладка» в панели разбора."); }
    else if (state.text || state.interval || view.stats.total) { title = t("Ничего не найдено"); text = t("Измените фильтр или выберите другой интервал."); }
    empty.innerHTML = `<span class="symbol" aria-hidden="true">${noteColumn() ? "☆" : "⌁"}</span><strong>${title}</strong><p>${text}</p>`;
  }
  const end = Math.min(view.offset + pageSize, view.total);
  $("range").textContent = view.total ? t("{from}–{to} из {total}", {from: formatNumber(view.offset + 1), to: formatNumber(end), total: formatNumber(view.total)}) : t("0 результатов");
  $("prev").disabled = view.offset === 0;
  $("next").disabled = end >= view.total;
  $("tail").classList.toggle("selected", state.latest);
  $("tail").setAttribute("aria-pressed", String(state.latest));
  $("tail").disabled = !view.running && !view.total;
}

function noteColumn() {
  return state.tab === "notes";
}

function renderChart(id, buckets) {
  const chart = $(id);
  const key = JSON.stringify([buckets, state.interval]);
  if (key === chartKeys.get(id) || chart.contains(document.activeElement)) return;
  chartKeys.set(id, key);
  if (!buckets.length) {
    chart.innerHTML = `<p class="muted">${t("График появится после захвата или открытия файла.")}</p>`;
    return;
  }
  const peak = Math.max(1, ...buckets.map(b => b.in + b.out + b.other));
  const bars = buckets.map(b => {
    const active = state.interval?.from === b.from && state.interval?.to === b.to;
    const duration = b.to - b.from;
    const title = `${intervalText(b)} · ${bytesPerSecond(b.in + b.out + b.other, duration)}`;
    const columns = ["in", "out", "other"].map(side => `<span class="${side}" style="height:${b[side] / peak * 100}%"></span>`).join("");
    return `<button class="${active ? "active" : ""}" data-from="${b.from}" data-to="${b.to}" title="${title}" aria-label="${title}" aria-pressed="${active}">${columns}</button>`;
  }).join("");
  chart.innerHTML = `<div class="chart-plot">${bars}</div><div class="chart-labels"><span>${buckets[0].from} ${t("с")}</span><span>${t("Пик")} ${bytesPerSecond(peak, buckets[0].to - buckets[0].from)}</span><span>${buckets.at(-1).to} ${t("с")}</span></div><div class="chart-legend"><span><i class="in"></i>${t("Входящий")}</span><span><i class="out"></i>${t("Исходящий")}</span><span><i class="other"></i>${t("Без направления")}</span></div>`;
}

function render() {
  const view = state.view;
  const stats = view.stats;
  const diagnosing = state.tab === "diagnose";
  const grouped = state.tab === "flows" && !state.flow;
  $("table-region").hidden = diagnosing;
  $("pager").hidden = diagnosing;
  $("diagnosis").hidden = !diagnosing;
  $("graph-large").hidden = state.tab !== "graph";
  document.querySelectorAll("[data-tab]").forEach(el => {
    el.classList.toggle("selected", el.dataset.tab === state.tab);
    el.setAttribute("aria-pressed", String(el.dataset.tab === state.tab));
  });
  document.querySelectorAll("[data-proto]").forEach(el => {
    el.classList.toggle("selected", state.text === el.dataset.proto);
    el.setAttribute("aria-pressed", String(state.text === el.dataset.proto));
  });
  $("filter-clear").hidden = !state.text;
  $("note-count").hidden = !stats.marked;
  $("note-count").textContent = stats.marked;
  $("count").textContent = formatNumber(stats.total);
  $("displayed").textContent = grouped ? t("{count} соедин.", {count: formatNumber(view.total)}) : diagnosing ? "—" : formatNumber(view.total);
  $("marked").textContent = formatNumber(stats.marked);
  $("dropped").textContent = stats.dropped < 0 ? "—" : formatNumber(stats.dropped);
  $("status-dot").classList.toggle("live", view.running);
  $("status-label").textContent = translateMessage(view.notice) || (view.running ? t("Идёт захват") : view.path ? t("Открыт файл") : view.interface ? t("Захват остановлен") : t("Готов к захвату"));
  $("status-file").textContent = view.interface || basename(view.path);
  $("status-file").title = view.path;
  $("status-bytes").textContent = size(stats.bytes);
  const protocols = stats.protocols ?? [];
  const key = JSON.stringify([stats.total, protocols]);
  if (sidebarKey !== key) {
    sidebarKey = key;
    $("protocols").innerHTML = protocols.length ? protocols.slice(0, 8).map(item => {
      const percent = item.count / stats.total * 100;
      return `<div class="protocol-row"><span>${escape(item.name)}</span><meter max="100" value="${percent}" aria-label="${escape(item.name)}"></meter><span>${percent.toFixed(1)}%</span></div>`;
    }).join("") : t("Нет данных");
  }
  showScope();
  if (!diagnosing) {
    renderTable(view);
    const selected = view.packets?.find(packet => packet.id === state.selected);
    if (selected?.process && state.detail?.packet.id === selected.id && !state.detail.packet.process) {
      state.detail.packet.process = selected.process;
      renderPacketOwner();
    }
    if (state.latest) {
      const region = $("table-region");
      region.scrollTop = region.scrollHeight;
    }
  }
  renderChart("graph-small", view.graph ?? []);
  if (state.tab === "graph") renderChart("graph-large", view.graph ?? []);
  updateButtons();
}

function renderPacketOwner() {
  const label = $("packet-owner");
  const packet = state.detail?.packet;
  label.hidden = !packet || !state.view?.interface;
  label.textContent = packet ? `${t("Процесс")} · ${processName(packet.process)}` : "";
  label.title = packet?.process ? t("Владелец локального сокета") : t("Владелец сокета неизвестен");
}

function renderDetail() {
  const detail = state.detail;
  $("inspect-request").disabled = !detail?.canInspectRequest;
  renderPacketOwner();
  $("note").disabled = !detail;
  $("note").textContent = detail?.packet.marked ? t("★ Заметка") : t("☆ Закладка");
  $("hex-meta").textContent = detail ? size(detail.packet.length) : "";
  $("hex").textContent = detail?.hex || t("Здесь появится HEX и ASCII выбранного пакета");
  $("hex").classList.toggle("muted", !detail);
  $("layers").classList.toggle("muted", !detail);
  if (!detail) {
    $("layers").textContent = state.selected ? t("Читаем пакет…") : t("Выберите пакет в таблице");
    return;
  }
  const packet = detail.packet;
  const note = packet.note ? `<p class="packet-note"><strong>${t("Заметка")}</strong> ${escape(packet.note)}</p>` : "";
  const layers = detail.layers.map((layer, index) =>
    `<details${state.mode === "advanced" && index === 0 ? " open" : ""}><summary>${escape(t(layer.name))}</summary><pre>${escape(layer.name === "Кадр" ? translateMessage(layer.text) : layer.text)}</pre></details>`).join("");
  if (state.mode === "simple") {
    $("layers").innerHTML = `<p><strong>${escape(translateMessage(packet.event))}</strong> · #${packet.id}</p><p class="summary-info">${escape(packet.info)}</p>${note}<details><summary>${t("Технические детали")}</summary>${layers}</details>`;
  } else {
    $("layers").innerHTML = note + layers;
  }
}

async function selectPacket(id) {
  const request = ++detailRequest;
  state.selected = id;
  state.detail = null;
  renderDetail();
  if (state.view && state.tab !== "diagnose") renderTable(state.view);
  try {
    const detail = await call("Detail", id);
    if (request !== detailRequest) return;
    state.detail = detail;
    renderDetail();
  } catch (error) {
    if (request === detailRequest) showError(error);
  }
}

function appendRequestText(parent, tag, value, className) {
  const element = document.createElement(tag);
  element.textContent = value;
  if (className) element.className = className;
  parent.append(element);
  return element;
}

function renderRequestPreview(parent, preview) {
  if (preview.kind === "multipart") return;
  if (preview.kind === "empty") {
    appendRequestText(parent, "p", t("Тело запроса пустое"), "muted");
    return;
  }
  if (preview.kind === "binary" || preview.kind === "encoded") {
    const label = preview.kind === "binary" ? "Двоичные данные" : "Кодировка тела пока не поддерживается";
    appendRequestText(parent, "p", t(label), "muted");
    return;
  }
  appendRequestText(parent, "h3", preview.kind === "json" ? "JSON" : t("Текст"));
  if (preview.text) appendRequestText(parent, "pre", preview.text);
  if (preview.truncated) appendRequestText(parent, "p", t("Предпросмотр сокращён"), "muted");
}

function renderRequestContent() {
  const panel = $("request-result");
  const status = $("request-status");
  panel.replaceChildren();
  const requests = requestContents?.requests ?? [];
  const selected = requests[Number($("request-choice").value)];
  const notices = [];
  if (requestContents?.encrypted && !selected) {
    notices.push(t("Содержимое HTTPS зашифровано"));
  } else if (requestContents && !selected) {
    notices.push(t("В захвате нет читаемого запроса HTTP/1.x для этого соединения"));
  }
  if (requestContents?.incomplete || selected?.incomplete) notices.push(t("Часть запроса или TCP-потока отсутствует в захвате"));
  if (requestContents?.limited || selected?.limited) notices.push(t("Достигнут предел размера или количества запросов для просмотра"));
  status.textContent = notices.join(" · ");
  status.hidden = !notices.length;
  if (!selected) return;
  appendRequestText(panel, "code", [selected.method + " " + selected.target, selected.host].filter(Boolean).join(" · "));
  if (selected.contentType) appendRequestText(panel, "code", selected.contentType, "muted");
  if (selected.filename) appendRequestText(panel, "strong", selected.filename);
  renderRequestPreview(panel, selected.body);
  for (const part of selected.parts ?? []) {
    const item = appendRequestText(panel, "section", "", "request-part");
    appendRequestText(item, "strong", [part.field, part.filename].filter(Boolean).join(" · ") || t("Часть формы"));
    if (part.contentType) appendRequestText(item, "code", part.contentType, "muted");
    renderRequestPreview(item, part.body);
  }
}

async function loadRequestContent() {
  const request = ++contentRequest;
  const dialog = $("request-dialog");
  const choices = $("request-choice");
  const status = $("request-status");
  const refreshButton = $("refresh-request");
  refreshButton.disabled = true;
  choices.hidden = true;
  choices.replaceChildren();
  $("request-result").replaceChildren();
  status.textContent = t("Собираем запрос…");
  status.hidden = false;
  try {
    const result = await call("RequestContent", requestPacket);
    if (request !== contentRequest || !dialog.open) return;
    requestContents = result;
    let closest = 0;
    let closestPacket = 0;
    for (const [index, item] of (result.requests ?? []).entries()) {
      choices.append(new Option(`#${item.packet} · ${item.method} ${item.target}`, String(index)));
      if (item.packet > closestPacket && item.packet <= requestPacket) {
        closest = index;
        closestPacket = item.packet;
      }
    }
    choices.value = String(result.selected ? result.selected - 1 : closest);
    choices.hidden = choices.options.length < 2;
    renderRequestContent();
  } catch (error) {
    if (request !== contentRequest || !dialog.open) return;
    status.textContent = translateMessage(error?.message ?? String(error));
  } finally {
    if (request === contentRequest) refreshButton.disabled = false;
  }
}

function showRequestContent() {
  if (!state.detail?.canInspectRequest) return;
  requestPacket = state.detail.packet.id;
  requestContents = null;
  $("request-dialog").showModal();
  void loadRequestContent();
}

function resetPage(latest = false) {
  state.offset = 0;
  state.latest = latest;
  $("table-region").scrollTop = 0;
}

function setTab(tab) {
  state.tab = tab;
  state.flow = 0;
  resetPage(tab === "packets" && !state.text && !state.interval);
  return changeView();
}

function applyText(text) {
  $("display").value = text;
  state.text = text.trim();
  const follow = state.tab === "packets" && state.latest && !state.interval;
  if (state.tab === "diagnose") state.tab = "packets";
  resetPage(follow);
  return changeView();
}

function clearSessionView() {
  ++detailRequest;
  state.tab = "packets";
  state.flow = 0;
  state.text = "";
  $("display").value = "";
  state.interval = null;
  state.selected = 0;
  state.detail = null;
  state.dirtyNotes = false;
  state.diagnosis = null;
  renderDiagnosis();
  renderDetail();
  resetPage(true);
  return changeView();
}

function confirmAction(title, message, button) {
  const dialog = $("confirm-dialog");
  $("confirm-title").textContent = title;
  $("confirm-text").textContent = message;
  $("confirm-go").textContent = button;
  dialog.returnValue = "";
  return new Promise(resolve => {
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "go"), {once: true});
    dialog.showModal();
  });
}

async function allowReplacement() {
  return !state.dirtyNotes || await confirmAction(t("Есть несохранённые заметки"), t("Заметки из этого сеанса можно сохранить в PCAPNG."), t("Продолжить"));
}

async function startCapture(restart) {
  await run(async () => {
    if (!await allowReplacement()) return;
    if (restart && state.view?.running) await call("StopCapture");
    const device = $("device").value;
    const filter = state.mode === "advanced" ? $("capture-filter").value.trim() : "";
    let status = await call("StartCapture", device, filter);
    if (status === "permission") {
      const accepted = await confirmAction(
        t("Нужны права на захват"),
        t("LFish запросит через PolicyKit разрешение CAP_NET_RAW для процесса захвата и повторит запуск после подтверждения."),
        t("Запросить права"),
      );
      if (!accepted || !await call("GrantCapturePermission")) return;
      status = await call("StartCapture", device, filter);
      if (status === "permission") throw new Error(t("После подтверждения доступ к захвату по-прежнему отсутствует."));
    }
    await clearSessionView();
  });
}

function openCapture() {
  return run(async () => {
    if (!await allowReplacement()) return;
    if (await call("OpenCapture")) await clearSessionView();
  });
}

function saveCapture() {
  return run(async () => {
    const format = $("format").value;
    if (format === "pcap" && state.view?.stats.marked) {
      if (!await confirmAction(t("Экспорт в PCAP"), t("Формат PCAP хранит пакеты. Чтобы сохранить ещё и заметки, выберите PCAPNG."), t("Сохранить PCAP"))) return;
    }
    const path = await call("SaveCapture", format);
    if (path) {
      if (format === "pcapng") state.dirtyNotes = false;
      toast(t("Захват сохранён · {name}", {name: basename(path)}));
    }
  });
}

function showNote() {
  if (!state.detail) return;
  const packet = state.detail.packet;
  $("note-title").textContent = t("Закладка пакета #{id}", {id: packet.id});
  $("note-text").value = packet.note;
  $("note-dialog").dataset.packet = packet.id;
  $("note-error").hidden = true;
  $("delete-note").hidden = !packet.marked;
  $("note-dialog").showModal();
  $("note-text").focus();
}

async function saveNote(note, marked = true) {
  const dialog = $("note-dialog");
  if (dialog.dataset.saving === "true") return;
  dialog.dataset.saving = "true";
  const id = Number(dialog.dataset.packet);
  try {
    await call("SetNote", id, note, marked);
    const previous = state.detail?.packet;
    if (previous?.note !== note.trim() || previous?.marked !== marked) state.dirtyNotes = true;
    dialog.close();
    await selectPacket(id);
    await changeView();
  } catch (error) {
    $("note-error").textContent = translateMessage(error?.message ?? String(error));
    $("note-error").hidden = false;
  } finally {
    delete dialog.dataset.saving;
  }
}

function stage(label, result) {
  return `<div class="stage ${escape(result.state)}"><strong>${label}</strong><span>${escape(translateMessage(result.text))}</span>${result.packet ? `<button data-evidence="${result.packet}" title="${t("Показать пакет")}">#${result.packet}</button>` : ""}</div>`;
}

async function diagnose(event) {
  event.preventDefault();
  const target = $("target").value.trim();
  try {
    state.diagnosis = await call("Diagnose", target);
    renderDiagnosis();
  } catch (error) {
    showError(error);
  }
}

function renderDiagnosis() {
  const result = state.diagnosis;
  if (!result) {
    $("diagnosis-result").replaceChildren();
    return;
  }
  const connections = result.connections ?? [];
  const items = connections.map((item, index) =>
    `<details class="diagnostic-flow"${index === 0 ? " open" : ""}><summary>#${item.flow} · ${escape(item.destination)}</summary>${stage("TCP", item.tcp)}${stage("TLS", item.tls)}</details>`).join("");
  let status = "";
  if (!connections.length) status = t("Связанные TCP-соединения не видны. Если известен IP-адрес сайта, проверьте его отдельно.");
  else if (result.more) status = t("Ещё соединений: {count}. Все соединения доступны на вкладке «Соединения».", {count: formatNumber(result.more)});
  $("diagnosis-result").innerHTML = stage("DNS", result.dns) + items + (status ? `<p class="muted">${status}</p>` : "");
}

function activateRow(target) {
  const row = target.closest("#tbody tr");
  if (!row) return;
  if (row.dataset.packet) void selectPacket(Number(row.dataset.packet));
  if (row.dataset.flow) {
    state.flow = Number(row.dataset.flow);
    resetPage();
    void changeView();
  }
}

function bindUI() {
  for (const id of ["start", "sidebar-start"]) $(id).onclick = () => startCapture(false);
  $("restart").onclick = () => startCapture(true);
  $("stop").onclick = () => run(() => call("StopCapture"));
  $("open").onclick = openCapture;
  $("save").onclick = saveCapture;
  $("interfaces").onclick = () => run(loadInterfaces);
  $("device").onchange = showAddresses;
  $("settings").onclick = () => {
    $("settings-error").hidden = true;
    $("settings-dialog").showModal();
  };
  $("language").onchange = event => savePreferences({language: event.target.value, theme: state.theme}, "settings-error");
  $("welcome-language").onchange = event => savePreferences({language: event.target.value, theme: state.theme}, "mode-error");
  $("theme").onchange = event => savePreferences({language, theme: event.target.value}, "settings-error");
  $("switch-mode").onclick = () => $("welcome").showModal();
  $("welcome").addEventListener("cancel", event => { if (!state.mode) event.preventDefault(); });
  document.querySelectorAll("[data-mode]").forEach(button => {
    button.onclick = async () => {
      try {
        await call("SetMode", button.dataset.mode);
        $("mode-error").hidden = true;
        await setMode(button.dataset.mode);
      } catch (error) {
        $("mode-error").textContent = translateMessage(error?.message ?? String(error));
        $("mode-error").hidden = false;
      }
    };
  });
  $("display").oninput = event => applyText(event.target.value);
  $("filter-clear").onclick = () => { void applyText(""); $("display").focus(); };
  $("filter-help").onclick = () => $("help-dialog").showModal();
  document.querySelectorAll("[data-proto]").forEach(button => { button.onclick = () => applyText(button.dataset.proto); });
  document.querySelectorAll("[data-tab]").forEach(button => { button.onclick = () => setTab(button.dataset.tab); });
  $("expand-chart").onclick = () => setTab("graph");
  $("scope").onclick = event => {
    const type = event.target.dataset.clear;
    if (!type) return;
    if (type === "flow") state.flow = 0;
    if (type === "interval") state.interval = null;
    resetPage();
    void changeView();
  };
  for (const id of ["graph-small", "graph-large"]) {
    $(id).onclick = event => {
      const button = event.target.closest("[data-from]");
      if (!button) return;
      state.interval = {from: Number(button.dataset.from), to: Number(button.dataset.to)};
      button.blur();
      if (id === "graph-small") void setTab("graph");
      else { resetPage(); void changeView(); }
    };
  }
  $("tbody").onclick = event => activateRow(event.target);
  $("tbody").onkeydown = event => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); activateRow(event.target); }
  };
  $("prev").onclick = () => { state.offset -= pageSize; state.latest = false; $("table-region").scrollTop = 0; void changeView(); };
  $("next").onclick = () => { state.offset += pageSize; state.latest = false; $("table-region").scrollTop = 0; void changeView(); };
  $("tail").onclick = () => { state.latest = !state.latest; void changeView(); };
  $("note").onclick = showNote;
  $("inspect-request").onclick = showRequestContent;
  $("refresh-request").onclick = loadRequestContent;
  $("request-choice").onchange = renderRequestContent;
  $("request-dialog").addEventListener("close", () => { contentRequest++; });
  $("note-form").onsubmit = event => { event.preventDefault(); void saveNote($("note-text").value); };
  $("delete-note").onclick = () => saveNote("", false);
  $("cancel-note").onclick = () => $("note-dialog").close();
  $("diagnose-form").onsubmit = diagnose;
  $("diagnosis-result").onclick = async event => {
    const id = Number(event.target.dataset.evidence);
    if (!id) return;
    state.flow = 0;
    state.interval = null;
    await applyText("id=" + id);
    await selectPacket(id);
  };
}

async function boot() {
  bindUI();
  let mode = "";
  try {
    await loadTranslations();
  } catch (error) {
    showError(error);
  }
  try {
    applyPreferences(await call("GetPreferences"));
  } catch (error) {
    showError(error);
  }
  try {
    mode = await call("GetMode");
    await loadInterfaces();
  } catch (error) {
    showError(error);
  }
  if (mode) await setMode(mode);
  else $("welcome").showModal();
  setInterval(() => {
    if (state.view?.running || state.busy) void refresh();
  }, 650);
}

void boot();
