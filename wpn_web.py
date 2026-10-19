#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wp-nuclear Web UI — dashboard local para auditoria/limpeza de WordPress via FTP.

Executa:   python3 wpn_web.py [--port 8787]
Abre:      http://localhost:8787

Interface segue Apple HIG (macOS): sidebar translúcida, system type, cores
semânticas, light/dark automáticos, alerts com confirmação digitada.
Dados informados no navegador nunca são persistidos (senhas ficam em memória).
"""
import argparse, io, json, os, re, sys, threading, traceback, uuid
from datetime import datetime
import urllib.parse

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
BACKUP_DIR = os.path.join(BASE_DIR, "wpn_backups")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

sys.path.insert(0, BASE_DIR)
import wp_nuclear as W

JOBS = {}
JOBS_LOCK = threading.Lock()

def make_ns(**kw):
    ns = argparse.Namespace()
    defaults = dict(host=None, user=None, password=None, port=21, path=None,
                    signatures=W.SIG_DEFAULT, backup=BACKUP_DIR, domain=None,
                    db_probe=False, json=None, html=None, report=None,
                    execute=False, resetpass=False, baseline=None, yes=False)
    defaults.update(kw)
    for k, v in defaults.items():
        setattr(ns, k, v)
    return ns

class CapturedPrint:
    """Captura stdout do comando para exibir no painel."""
    def __init__(self):
        self.buf = io.StringIO()
    def __enter__(self):
        self._old = sys.stdout
        sys.stdout = self.buf
        return self.buf
    def __exit__(self, *a):
        sys.stdout = self._old

def run_job(job_id, fn, ns):
    def work():
        job = JOBS[job_id]
        with JOBS_LOCK:
            job["status"] = "running"
        try:
            with CapturedPrint() as cap:
                result = fn(ns)
            with JOBS_LOCK:
                job["status"] = "done"
                job["result"] = result
        except SystemExit:
            with JOBS_LOCK:
                job["status"]="done"; job["error"]="comando pediu saída"
        except Exception as e:
            traceback.print_exc()
            with JOBS_LOCK:
                job["status"] = "error"
                job["error"] = str(e)
        finally:
            job["log"] = cap.getvalue().splitlines() if "cap" in locals() else []
    t = threading.Thread(target=work, daemon=True)
    t.start()
    return t

# ---------------------------------------------------------------- endpoints

def api_scan(payload):
    host = payload.get("host"); user = payload.get("user"); password = payload.get("password")
    domain = payload.get("domain"); port = int(payload.get("port") or 21)
    db_probe = bool(payload.get("db_probe"))
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = stamp + "_" + re.sub(r"[^a-z0-9.-]+","_",(domain or host).lower().replace("https://",""))[:40]
    jf = os.path.join(REPORTS_DIR, name + ".json")
    hf = os.path.join(REPORTS_DIR, name + ".html")
    ns = make_ns(host=host, user=user, password=password, port=port, domain=domain,
                 db_probe=db_probe, json=jf, html=hf)
    job_id = uuid.uuid4().hex[:10]
    with JOBS_LOCK:
        JOBS[job_id] = {"job_id":job_id,"type":"scan","status":"queued","started":datetime.now().isoformat(),
                        "report_json":os.path.basename(jf),"report_html":os.path.basename(hf),"log":[], "result":None,"error":None}
    run_job(job_id, W.cmd_scan, ns)
    return {"job_id":job_id}

def plan_from_reports(payload):
    rj = os.path.join(REPORTS_DIR, os.path.basename(payload.get("report","")))
    report = W.load_report(rj)
    F = report["findings"]
    to_move=[fd for fd in F if fd["severity"]=="high" and fd["kind"] in ("artifact","mu-plugin","plugin-stash","uploads-php","dir")]
    restore_index=any(fd["kind"]=="restore-needed" for fd in F)
    ht=[fd for fd in F if fd["kind"]=="htaccess" and fd["severity"]=="high"]
    return {"report":os.path.basename(rj), "host":report["host"], "user":report["user"],
            "port":report.get("port",21), "path":report["path"],
            "to_move":to_move, "restore_index":restore_index, "htaccess":ht}

def api_clean(payload):
    plan = plan_from_reports(payload)
    if not (plan["to_move"] or plan["restore_index"] or plan["htaccess"]):
        return {"noop":True, "plan":plan}
    confirm = (payload.get("confirm") or "").strip()
    if not payload.get("execute") and confirm!="LIMPAR":
        return {"need_confirm":True, "plan":plan}
    ns = make_ns(report=os.path.join(REPORTS_DIR, plan["report"]),
                 host=payload.get("host") or plan["host"], user=payload.get("user") or plan["user"],
                 password=payload.get("password"), port=int(payload.get("port") or plan["port"] or 21),
                 execute=True, yes=True, backup=BACKUP_DIR, json=None)
    job_id = uuid.uuid4().hex[:10]
    with JOBS_LOCK:
        JOBS[job_id]={"job_id":job_id,"type":"clean","status":"queued","started":datetime.now().isoformat(),"log":[],"result":None,"error":None,"plan":plan}
    run_job(job_id, W.cmd_clean, ns)
    return {"job_id":job_id, "plan":plan}

def api_salts(payload):
    confirm=(payload.get("confirm") or "").strip()
    if confirm!="SALTS":
        return {"need_confirm":True}
    ns=make_ns(host=payload["host"], user=payload["user"], password=payload["password"],
               port=int(payload.get("port") or 21), execute=True, yes=True, backup=BACKUP_DIR,
               report=os.path.join(REPORTS_DIR, os.path.basename(payload.get("report") or "")))
    job_id=uuid.uuid4().hex[:10]
    with JOBS_LOCK:
        JOBS[job_id]={"job_id":job_id,"type":"salts","status":"queued","started":datetime.now().isoformat(),"log":[],"result":None,"error":None}
    run_job(job_id, W.cmd_salts, ns)
    return {"job_id":job_id}

def api_db(payload):
    domain=payload.get("domain")
    if not domain: return {"error":"informe o domínio https://… para o probe do banco"}
    ns=make_ns(host=payload["host"], user=payload["user"], password=payload["password"],
               port=int(payload.get("port") or 21), domain=(domain if "://" in domain else "https://"+domain),
               execute=bool(payload.get("execute")), resetpass=bool(payload.get("resetpass")),
               report=os.path.join(REPORTS_DIR, os.path.basename(payload.get("report") or "")))
    job_id=uuid.uuid4().hex[:10]
    with JOBS_LOCK:
        JOBS[job_id]={"job_id":job_id,"type":"db","status":"queued","started":datetime.now().isoformat(),"log":[],"result":None,"error":None}
    run_job(job_id, W.cmd_db, ns)
    return {"job_id":job_id}

def api_job_get(job_id):
    with JOBS_LOCK:
        j = json.loads(json.dumps(JOBS.get(job_id, {})))
    return j

def api_list():
    with JOBS_LOCK:
        brief=[]
        for k in sorted(JOBS, reverse=True):
            j=dict(JOBS[k])
            j["log"]=(j.get("log") or [])[:3]
            j.pop("result",None); j.pop("plan",None)
            brief.append(j)
    return brief

def api_reports_list():
    out=[]
    for fn in sorted(os.listdir(REPORTS_DIR), reverse=True)[:60]:
        if not fn.endswith((".json",".html")): continue
        p=os.path.join(REPORTS_DIR,fn); out.append({"file":fn,"size":os.path.getsize(p) if os.path.exists(p) else 0})
    return out

# ---------------------------------------------------------------- server page
# Design: Apple HIG (macOS) — sidebar translúcida sobre Liquid Glass, system type,
# cores semânticas, light/dark automáticos, alert sheets com confirm digitado.

PAGE = r"""<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wp-nuclear</title>
<style>
/* tokens — Apple system colors, light + dark (dark-mode.md › Semantic colors) */
:root{
  --win:#f5f5f7; --content:#ffffff; --side:rgba(242,242,247,.78);
  --text:#1d1d1f; --text2:#6e6e73; --text3:#aeaeb2;
  --sep:rgba(0,0,0,.11); --sep-strong:rgba(0,0,0,.16);
  --card:#ffffff; --hover:rgba(0,0,0,.045); --field:#f5f5f7;
  --accent:#007aff; --accent-soft:rgba(0,122,255,.10);
  --red:#ff3b30;  --red-soft:rgba(255,59,48,.10);
  --orange:#ff9500; --orange-soft:rgba(255,149,0,.12);
  --green:#34c759; --green-soft:rgba(52,199,89,.12);
  --yellow:#ffcc00;
  --shadow:0 8px 32px rgba(0,0,0,.10);
}
@media (prefers-color-scheme: dark){
  :root{
    --win:#1a1a1c; --content:#232326; --side:rgba(30,30,34,.72);
    --text:#f5f5f7; --text2:#98989f; --text3:#6b6b70;
    --sep:rgba(255,255,255,.10); --sep-strong:rgba(255,255,255,.18);
    --card:#2c2c30; --hover:rgba(255,255,255,.06); --field:#1c1c1e;
    --accent:#0a84ff; --accent-soft:rgba(10,132,255,.16);
    --red:#ff453a;  --red-soft:rgba(255,69,58,.16);
    --orange:#ff9f0a; --orange-soft:rgba(255,159,10,.16);
    --green:#30d158; --green-soft:rgba(48,209,88,.16);
    --yellow:#ffd60a;
    --shadow:0 8px 32px rgba(0,0,0,.5);
  }
}
@media (prefers-reduced-transparency: reduce){
  :root{ --side:var(--win); }
}
*{box-sizing:border-box; margin:0}
html,body{height:100%}
body{
  background:var(--win); color:var(--text); overflow:hidden;
  font:13px/1.47 -apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue","Segoe UI",Roboto,sans-serif;
  -webkit-font-smoothing:antialiased;
}
/* ————— janela macOS ————— */
.window{
  height:100vh; display:flex; flex-direction:column;
  padding:0; max-width:1240px; margin:0 auto;
}
@media(min-width:1100px){
  .window{ padding:14px 16px }
  .frame{
    height:calc(100vh - 28px);
    border-radius:12px; background:var(--content);
    box-shadow:var(--shadow); border:.5px solid var(--sep-strong);
    overflow:hidden; display:flex; flex-direction:column;
  }
}
@media(max-width:1099px){
  .frame{ height:100vh; display:flex; flex-direction:column; background:var(--content) }
}
/* toolbar */
.toolbar{
  display:flex; align-items:center; gap:10px; height:52px; padding:0 14px;
  border-bottom:.5px solid var(--sep);
  background:linear-gradient(to bottom, rgba(255,255,255,.06), transparent);
  flex-shrink:0; position:relative;
  -webkit-app-region:drag;
}
@media (prefers-color-scheme: light){ .toolbar{ background:#f2f2f4 } }
.lights{display:flex; gap:8px; min-width:56px}
.lights span{width:12px;height:12px;border-radius:50%}
.lights .r{background:#ff5f57}.lights .y{background:#febc2e}.lights .g{background:#28c840}
.toolbar .title{
  position:absolute; left:50%; transform:translateX(-50%);
  font-size:13px; font-weight:600; color:var(--text2); pointer-events:none; white-space:nowrap;
}
.toolbar .title b{color:var(--text); font-weight:600}
.toolbar .right{margin-left:auto; display:flex; align-items:center; gap:8px}
.spin{width:15px;height:15px;border:2px solid var(--sep);border-top-color:var(--accent);border-radius:50%;animation:sp .8s linear infinite;display:none}
.spin.on{display:inline-block}
@keyframes sp{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion: reduce){ .spin{animation-duration:2.5s} }
/* corpo: sidebar + main */
.body{flex:1; display:flex; min-height:0}
.sidebar{
  width:228px; flex-shrink:0; padding:10px 10px 12px;
  background:var(--side);
  backdrop-filter:blur(28px) saturate(1.8); -webkit-backdrop-filter:blur(28px) saturate(1.8);
  border-right:.5px solid var(--sep);
  display:flex; flex-direction:column; gap:2px; overflow-y:auto;
}
.side-h{font-size:11px; font-weight:600; color:var(--text3); text-transform:uppercase; letter-spacing:.4px; margin:14px 8px 4px}
.side-h:first-child{margin-top:4px}
.nav{
  display:flex; align-items:center; gap:9px; padding:6px 9px; border-radius:7px;
  cursor:pointer; user-select:none; min-height:28px; color:var(--text); border:0; text-align:left;
  font:inherit; font-size:13px; background:transparent; width:100%;
}
.nav:hover{background:var(--hover)}
.nav.on{background:var(--accent)}
.nav.on .nl{color:#fff; font-weight:500}
.nav svg{width:16px;height:16px;flex-shrink:0; stroke:var(--accent); fill:none; stroke-width:1.7}
.nav.on svg{stroke:#fff}
.nl{color:var(--text)}
.nav .cnt{margin-left:auto; font-size:11px; color:var(--text3); font-variant-numeric:tabular-nums}
.nav.on .cnt{color:rgba(255,255,255,.8)}
.side-foot{margin-top:auto; padding:0 9px; font-size:11px; color:var(--text3); line-height:1.6}
/* main */
.main{flex:1; overflow-y:auto; min-width:0}
.view{display:none; padding:22px 26px 40px; max-width:900px}
.view.on{display:block}
h2{font-size:17px; font-weight:700; letter-spacing:.2px; margin-bottom:2px}
.lede{color:var(--text2); font-size:13px; margin-bottom:18px}
/* hero de status — elemento de assinatura */
.hero{display:flex; align-items:center; gap:16px; margin-bottom:22px}
.seal{
  width:64px;height:64px;border-radius:50%;flex-shrink:0;position:relative;
  display:flex;align-items:center;justify-content:center;
  background:var(--green-soft); color:var(--green);
  transition:background .4s,color .4s;
}
.seal svg{width:28px;height:28px;stroke:currentColor;fill:none;stroke-width:1.8}
.seal.warn{background:var(--orange-soft); color:var(--orange)}
.seal.bad{background:var(--red-soft); color:var(--red)}
.seal.idle{background:var(--field); color:var(--text3)}
.seal.busy::after{
  content:"";position:absolute;inset:-4px;border-radius:50%;
  border:2px solid var(--accent);border-top-color:transparent;
  animation:sp 1s linear infinite;
}
@media (prefers-reduced-motion: reduce){ .seal.busy::after{display:none} }
.hero .st1{font-size:15px;font-weight:600}
.hero .st2{color:var(--text2); font-size:13px; margin-top:2px}
/* form agrupado estilo Settings */
.group{
  background:var(--card); border:.5px solid var(--sep); border-radius:10px;
  overflow:hidden; margin-bottom:16px;
}
.row{display:flex; align-items:center; gap:12px; padding:9px 14px; min-height:44px}
.row + .row{border-top:.5px solid var(--sep)}
.row label{flex:0 0 118px; font-size:13px; color:var(--text)}
.row label.fine{color:var(--text2)}
.row .inp{
  flex:1; min-width:0; background:var(--field); border:.5px solid var(--sep);
  border-radius:6px; padding:5px 9px; font:inherit; font-size:13px; color:var(--text); height:28px; outline:none;
}
.row .inp:focus{border-color:var(--accent); box-shadow:0 0 0 3px var(--accent-soft)}
.row .inp::placeholder{color:var(--text3)}
.row .hint{font-size:12px; color:var(--text3)}
.note{font-size:12px; color:var(--text2)}
/* botões */
.btn{
  font:inherit; font-size:13px; font-weight:500; border:0; border-radius:6px; cursor:pointer;
  min-height:28px; padding:4px 14px; display:inline-flex; align-items:center; gap:6px;
  transition:background .15s, transform .05s;
}
.btn:active{transform:scale(.985)}
.btn.primary{background:var(--accent); color:#fff}
.btn.primary:hover{filter:brightness(1.08)}
.btn.secondary{background:var(--hover); color:var(--text)}
.btn.secondary:hover{filter:brightness(.97)}
.btn.destructive{background:var(--red); color:#fff}
.btn.destructive:hover{filter:brightness(1.08)}
.btn.plain{background:transparent; color:var(--accent); padding:4px 8px}
.btn.plain:hover{background:var(--accent-soft)}
.btn:disabled{opacity:.42; cursor:default}
@media (prefers-reduced-motion: reduce){ .btn{transition:none} }
.btn:focus-visible,.nav:focus-visible,.row .inp:focus-visible{outline:2px solid var(--accent); outline-offset:2px}
/* console de log */
.console{
  background:var(--field); border:.5px solid var(--sep); border-radius:10px;
  padding:12px 14px; font:11.5px/1.6 ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  color:var(--text2); max-height:280px; overflow:auto; white-space:pre-wrap; word-break:break-all;
}
.console .err{color:var(--red)}
.console .ok{color:var(--green)}
/* achados */
.f-row{display:flex; align-items:flex-start; gap:11px; padding:10px 14px}
.f-row + .f-row{border-top:.5px solid var(--sep)}
.dot{width:9px;height:9px;border-radius:50%;margin-top:4px;flex-shrink:0}
.d-high{background:var(--red)} .d-warn{background:var(--orange)}
.d-review{background:var(--yellow)} .d-ok{background:var(--green)}
.d-queued{background:var(--text3)} .d-running{background:var(--orange)}
.d-done{background:var(--green)} .d-error{background:var(--red)}
.f-row .fp{font-family:ui-monospace,"SF Mono",Menlo,monospace; font-size:11.5px; word-break:break-all}
.f-row .fm{font-size:12px; color:var(--text2)}
.f-row .grow{flex:1; min-width:0}
.pill{font-size:10.5px;font-weight:600;padding:2px 8px;border-radius:10px;flex-shrink:0;margin-top:1px}
.p-high{background:var(--red-soft);color:var(--red)}
.p-warn{background:var(--orange-soft);color:var(--orange)}
.p-review{background:rgba(255,204,0,.16);color:#9a6b00}
.p-pill-ok{background:var(--green-soft);color:var(--green)}
@media (prefers-color-scheme: dark){ .p-review{color:var(--yellow)} }
.tag{font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.4px}
/* listas e estado vazio */
.empty{padding:34px 0; text-align:center; color:var(--text3); font-size:13px}
.empty svg{width:34px;height:34px;stroke:var(--text3);fill:none;stroke-width:1.4;margin-bottom:8px}
.r-item{display:flex; align-items:center; gap:11px; padding:9px 14px; cursor:pointer; border:0; background:none; width:100%; text-align:left; font:inherit}
.r-item:hover{background:var(--hover)}
.r-item + .r-item{border-top:.5px solid var(--sep)}
.r-item svg{width:17px;height:17px;stroke:var(--accent);fill:none;stroke-width:1.6;flex-shrink:0}
.r-item .rn{font-size:13px}
.r-item .rs{font-size:11px;color:var(--text3);font-variant-numeric:tabular-nums}
.actions{display:flex; gap:8px; flex-wrap:wrap; margin-top:14px}
/* alert sheet estilo macOS */
.sheet-back{
  display:none; position:fixed; inset:0; z-index:60;
  background:rgba(0,0,0,.32);
  align-items:center; justify-content:center;
}
.sheet-back.on{display:flex}
.sheet{
  width:400px; max-width:calc(100vw - 32px);
  background:var(--content); border-radius:12px; box-shadow:var(--shadow);
  border:.5px solid var(--sep-strong); padding:20px 18px 14px;
  outline:none;
}
.sheet h3{font-size:13px; font-weight:700; margin-bottom:6px; display:flex; align-items:center; gap:8px}
.sheet h3 svg{width:15px;height:15px;stroke:var(--red);fill:none;stroke-width:1.8}
.sheet .sbody{font-size:12.5px; color:var(--text2); line-height:1.55; max-height:300px; overflow:auto}
.sheet .sbody .path{font-family:ui-monospace,"SF Mono",Menlo,monospace; font-size:11px; color:var(--red); display:block; padding-left:10px}
.sheet .field{margin-top:12px}
.sheet .field label{font-size:12px; color:var(--text); display:block; margin-bottom:4px}
.sheet .field input{
  width:100%; background:var(--field); border:.5px solid var(--sep); border-radius:6px;
  height:28px; padding:4px 9px; font:inherit; font-size:13px; color:var(--text); outline:none;
}
.sheet .field input:focus{border-color:var(--accent); box-shadow:0 0 0 3px var(--accent-soft)}
.sheet .btns{display:flex; justify-content:flex-end; gap:8px; margin-top:16px}
kbd{font:11px ui-monospace,Menlo,monospace; background:var(--field); border:.5px solid var(--sep); border-bottom-width:1.5px; border-radius:4px; padding:1px 5px}
/* responsivo */
@media(max-width:720px){
  .sidebar{width:64px}
  .sidebar .nl,.sidebar .cnt,.side-h,.side-foot{display:none}
  .view{padding:16px}
}
</style>
</head>
<body>
<div class="window"><div class="frame">

  <!-- toolbar (windows.md › window controls) -->
  <div class="toolbar">
    <div class="lights"><span class="r"></span><span class="y"></span><span class="g"></span></div>
    <div class="title"><b>wp-nuclear</b>&nbsp; — auditoria e limpeza de WordPress</div>
    <div class="right"><span class="spin" id="globalSpin"></span></div>
  </div>

  <div class="body">

    <!-- sidebar (sidebars.md › source lists) -->
    <nav class="sidebar" aria-label="Navegação">
      <div class="side-h">Operações</div>
      <button class="nav on" data-view="scan" id="navScan">
        <svg viewBox="0 0 24 24"><path d="M12 3l7 3.2v5.1c0 4.6-3 8.2-7 9.7-4-1.5-7-5.1-7-9.7V6.2L12 3z" stroke-linejoin="round"/></svg>
        <span class="nl">Auditoria</span>
      </button>
      <button class="nav" data-view="reports" id="navReports">
        <svg viewBox="0 0 24 24"><path d="M6 3h8l4 4v14H6V3z" stroke-linejoin="round"/><path d="M9 12h6M9 16h6"/></svg>
        <span class="nl">Relatórios</span><span class="cnt" id="cntReports">0</span>
      </button>
      <button class="nav" data-view="jobs">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2.2"/></svg>
        <span class="nl">Atividade</span>
      </button>
      <div class="side-h">Ações rápidas</div>
      <button class="nav" id="navSalts">
        <svg viewBox="0 0 24 24"><circle cx="8" cy="14" r="4.5"/><path d="M11.5 11L19 3.5M15 5.5l2.5 2.5M17.5 3l3.5 3.5-2 2"/></svg>
        <span class="nl">Rotacionar salts</span>
      </button>
      <button class="nav" id="navDb">
        <svg viewBox="0 0 24 24"><ellipse cx="12" cy="5.5" rx="7.5" ry="2.8"/><path d="M4.5 5.5v13c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8v-13M4.5 12c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8"/></svg>
        <span class="nl">Banco de dados</span>
      </button>
      <div class="side-foot">
        v1 · executa local em 127.0.0.1<br>
        senhas não são gravadas em disco
      </div>
    </nav>

    <div class="main">

      <!-- ————— AUDITORIA ————— -->
      <section class="view on" id="view-scan">
        <h2>Auditoria</h2>
        <p class="lede">Escaneia o site por arquivos de invasão, cloaking e usuários-fantasma.</p>

        <div class="hero">
          <div class="seal idle" id="seal">
            <svg viewBox="0 0 24 24"><path d="M12 3l7 3.2v5.1c0 4.6-3 8.2-7 9.7-4-1.5-7-5.1-7-9.7V6.2L12 3z" stroke-linejoin="round"/><path d="M9 12.2l2.2 2.2L15.6 10" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </div>
          <div>
            <div class="st1" id="sealTitle">Pronto para escanear</div>
            <div class="st2" id="sealSub">Conecte-se a um site e inicie a auditoria.</div>
          </div>
        </div>

        <form id="scanForm">
          <div class="group">
            <div class="row">
              <label for="host">Host FTP</label>
              <input class="inp" id="host" placeholder="ex.: ftp.seudominio.com.br" autocomplete="off" spellcheck="false" list="hosts">
              <datalist id="hosts"></datalist>
            </div>
            <div class="row">
              <label for="user">Usuário</label>
              <input class="inp" id="user" placeholder="u000000000.dominio.com.br" autocomplete="off" spellcheck="false">
            </div>
            <div class="row">
              <label for="password">Senha</label>
              <input class="inp" id="password" type="password" autocomplete="new-password">
              <span class="hint">fica em memória</span>
            </div>
            <div class="row">
              <label for="port">Porta</label>
              <input class="inp" id="port" value="21" inputmode="numeric" style="flex:0 0 90px">
              <span class="note" style="flex:1; text-align:right">21 (FTP) · 65002 (SFTP em breve)</span>
            </div>
            <div class="row">
              <label for="domain">Domínio</label>
              <input class="inp" id="domain" placeholder="https://seusite.com.br" spellcheck="false">
              <span class="hint">ativa o banco</span>
            </div>
          </div>
          <div class="actions">
            <button type="submit" class="btn primary" id="btnScan">Escanear Site</button>
          </div>
        </form>

        <div class="actions" id="postScanActions" style="display:none">
          <button class="btn secondary" id="btnOpenReport">Ver Relatório Completo</button>
          <button class="btn secondary" id="btnQuickClean">Limpar Achados</button>
        </div>

        <div style="margin-top:18px">
          <div class="console" id="scanLog" hidden></div>
        </div>
      </section>

      <!-- ————— RELATÓRIOS ————— -->
      <section class="view" id="view-reports">
        <h2>Relatórios</h2>
        <p class="lede">Resultado de cada auditoria. Selecione para ver os achados.</p>
        <div class="group" id="reportsList"><div class="empty">Nenhum relatório ainda</div></div>
        <div id="findingsBox"></div>
      </section>

      <!-- ————— ATIVIDADE ————— -->
      <section class="view" id="view-jobs">
        <h2>Atividade</h2>
        <p class="lede">Execuções desta sessão — auditorias, limpezas e rotações.</p>
        <div class="group" id="jobsList"><div class="empty">Nenhuma execução ainda</div></div>
      </section>

    </div>
  </div>
</div></div>

<!-- alert sheet (alerts.md › destructive actions) -->
<div class="sheet-back" id="sheetBack">
  <div class="sheet" role="alertdialog" aria-modal="true" tabindex="-1">
    <h3 id="sheetTitle"><svg viewBox="0 0 24 24"><path d="M12 3L2.5 20h19L12 3z" stroke-linejoin="round"/><path d="M12 10v4.5" stroke-linecap="round"/><circle cx="12" cy="17.3" r=".2"/></svg><span id="sheetTitleText">Confirmar</span></h3>
    <div class="sbody" id="sheetBody"></div>
    <div class="field" id="sheetField">
      <label>Digite <b id="sheetWord">LIMPAR</b> para confirmar</label>
      <input id="sheetInput" autocomplete="off" spellcheck="false">
    </div>
    <div class="btns">
      <button class="btn secondary" id="sheetCancel">Cancelar</button>
      <button class="btn destructive" id="sheetOk">Confirmar</button>
    </div>
  </div>
</div>

<script>
const $=id=>document.getElementById(id);
let lastReport=null, scanning=false;

/* ————— navegação da sidebar ————— */
document.querySelectorAll('.nav[data-view]').forEach(b=>{
  b.onclick=()=>{
    document.querySelectorAll('.nav').forEach(x=>x.classList.remove('on'));
    document.querySelectorAll('.view').forEach(v=>v.classList.remove('on'));
    b.classList.add('on'); $('view-'+b.dataset.view).classList.add('on');
  };
});
function goto(view){ /* atalho: clique programático no item da sidebar */ }

/* ————— api ————— */
async function api(path, body){
  const r=await fetch(path, body?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:undefined);
  return r.json();
}

/* ————— sites recentes (localStorage, sem senha) ————— */
const SITES='wpn_sites';
function loadSites(){
  return JSON.parse(localStorage.getItem(SITES)||'[]');
}
function rememberSite(h,u,p){
  if(!h) return;
  const list=loadSites().filter(s=>!(s.host===h&&s.user===u));
  list.unshift({host:h,user:u,port:p});
  localStorage.setItem(SITES,JSON.stringify(list.slice(0,6)));
  renderDatalist();
}
function renderDatalist(){
  $('hosts').innerHTML=loadSites().map(s=>`<option value="${s.host}">`).join('');
}

/* ————— scanner ————— */
$('scanForm').onsubmit=async e=>{
  e.preventDefault();
  if(scanning) return;
  scanning=true;
  $('btnScan').disabled=true;
  $('globalSpin').classList.add('on');
  seal('busy','Escaneando…','Conectando ao servidor FTP.');
  const log=$('scanLog'); log.hidden=false; log.textContent=' ';
  rememberSite($('host').value.trim(), $('user').value.trim(), $('port').value.trim());
  try{
    const res=await api('/api/scan',{host:$('host').value.trim(),user:$('user').value.trim(),
      password:$('password').value,port:$('port').value.trim(),domain:$('domain').value.trim(),
      db_probe:!!$('domain').value.trim()});
    if(!res.job_id){ seal('idle','Pronto para escanear','Conecte-se a um site e inicie a auditoria.'); throw Object.assign(new Error(res.error||'falhou'),{srv:res}); }
    pollJob(res.job_id, log, j=>{ onScanDone(j); });
  }catch(err){
    scanning=false;
    seal('bad','Não foi possível iniciar', err.message);
    log.innerHTML='<span class="err">'+esc(err.message)+'</span>';
    $('globalSpin').classList.remove('on');
  }
};

function seal(state,title,sub){
  const s=$('seal');
  s.className='seal '+state;
  if(state==='busy') s.classList.add('busy');
  $('sealTitle').textContent=title;
  $('sealSub').textContent=sub||'';
}

function onScanDone(j){
  scanning=false; $('btnScan').disabled=false; $('globalSpin').classList.remove('on');
  const db=(j.result&&j.result.db)||{};
  const F=j.result?j.result.findings||[]:[];
  const ghosts=(db.ghosts||[]).length;
  if(F.length||ghosts){
    seal('bad', F.length+' ameaça'+(F.length>1?'s':'')+' encontrada'+(F.length>1?'s':''),
      'Limpeza necessária — veja o relatório.');
  }else{
    seal(S_REVIEW_LEN(j)>0?'warn':'ok','Site limpo','Nenhum item de alta gravidade.');
  }
  $('postScanActions').style.display='flex';
}

function S_REVIEW_LEN(j){return (j.result&&j.result.findings||[]).filter(f=>f.severity==='review').length}

function pollJob(id, logEl, done){
  const t=setInterval(async()=>{
    const j=await api('/api/job/'+id);
    if(logEl){
      const lines=j.log||[];
      logEl.innerHTML=lines.slice(-40).map(l=>esc(l)).join('\n');
      // marca fim p/ cores
      if(j.status==='done') logEl.innerHTML=lines.map(l=>esc(l)).join('\n');
      logEl.scrollTop=logEl.scrollHeight;
    }
    if(['done','error'].includes(j.status)){
      clearInterval(t);
      $('globalSpin').classList.remove('on');
      if(j.status==='error'&&logEl){
        logEl.innerHTML=(logEl.textContent||'').concat('\n').concat('ERRO: '+j.error).trim();
      }
      loadJobs(); loadReports();
      if(done) done(j);
    }
  },1500);
}

function esc(s){const d=document.createElement('div');d.textContent=s??'';return d.innerHTML}
function fmtSize(b){return b<1024?b+' B':b<1048576?Math.round(b/1024)+' KB':(b/1048576).toFixed(1)+' MB'}

/* ————— relatórios ————— */
async function loadReports(){
  const list=await api('/api/reports');
  $('cntReports').textContent=list.filter(r=>r.file.endsWith('.json')).length;
  const box=$('reportsList');
  if(!list.length){ box.innerHTML='<div class="empty">Nenhum relatório ainda</div>'; return; }
  box.innerHTML=list.filter(r=>r.file.endsWith('.json')).map(r=>`
    <button class="r-item" data-f="${r.file}">
      <svg viewBox="0 0 24 24"><path d="M6 3h8l4 4v14H6V3z" stroke-linejoin="round"/></svg>
      <span class="rn">${r.file}</span>
      <span class="rs" style="margin-left:auto">${fmtSize(r.size)}</span>
    </button>`).join('');
  box.querySelectorAll('.r-item').forEach(b=>{
    b.onclick=()=>openFindings(b.dataset.f);
  });
}

async function openFindings(file){
  const rep=await fetch('/report/'+encodeURIComponent(file)).then(r=>r.json());
  lastReport=file;
  const F=rep.findings||[];
  let h='';
  if(!F.length){
    h=`<div class="group" style="margin-top:16px"><div class="empty">
      <svg viewBox="0 0 24 24"><path d="M12 3l7 3.2v5.1c0 4.6-3 8.2-7 9.7-4-1.5-7-5.1-7-9.7V6.2L12 3z" stroke-linejoin="round"/><path d="M9 12.2l2.2 2.2L15.6 10" stroke-linecap="round"/></svg><br>
      Site limpo — nenhum item encontrado.</div></div>`;
  }else{
    const rows=F.map(f=>`
      <div class="f-row">
        <span class="dot d-${f.severity}"></span>
        <span class="grow"><div class="fp">${esc(f.path)}</div><div class="fm">${esc(f.msg)}</div></span>
        <span class="pill p-${f.severity}">${f.severity}</span>
      </div>`).join('');
    h=`<div class="group" style="margin-top:16px">${rows}</div>`;
  }
  const db=rep.db||{};
  if(db.users){
    const g=(db.ghosts||[]);
    h+=`<div class="note" style="margin-top:12px">Banco: ${db.users.length} usuário${db.users.length>1?'s':''} · `+
       (g.length?`<b style="color:var(--red)">${g.length} fantasma${g.length>1?'s':''}: ${g.map(x=>esc(x.login)).join(', ')}</b>`:'nenhum fantasma')+
       ` · senhas de aplicativo: ${(db.app_passwords||[]).length}</div>`;
  }
  $('findingsBox').innerHTML=h;
  if(!$('view-reports').classList.contains('on')) $('navReports').click();
}

/* ————— atividade ————— */
async function loadJobs(){
  const list=await api('/api/jobs');
  const box=$('jobsList');
  if(!list.length){ box.innerHTML='<div class="empty">Nenhuma execução ainda</div>'; return; }
  const TYPE={scan:'Auditoria',clean:'Limpeza',salts:'Rotacionar salts',db:'Banco de dados'};
  box.innerHTML=list.map(j=>`
    <div class="f-row">
      <span class="dot d-${j.status}"></span>
      <span class="grow"><div>${TYPE[j.type]||j.type} <span class="tag" style="margin-left:6px">${j.status}</span></div>
      <div class="fm">${new Date(j.started).toLocaleString('pt-BR')}</div></span>
      <span class="tag">${j.status==='running'?'executando':j.status==='done'?'concluído':'falhou'}</span>
    </div>`).join('');
}

/* ————— sheet de confirmação ————— */
let sheetAction=null;
function openSheet(title,word,bodyHtml,onOk,destructive){
  sheetAction=onOk;
  $('sheetTitleText').textContent=title;
  $('sheetWord').textContent=word;
  $('sheetBody').innerHTML=bodyHtml;
  $('sheetOk').className='btn '+(destructive?'destructive':'primary');
  $('sheetInput').value='';
  $('sheetBack').classList.add('on');
  $('sheetInput').focus();
}
function closeSheet(){ $('sheetBack').classList.remove('on'); }
$('sheetCancel').onclick=closeSheet;
$('sheetBack').onclick=e=>{ if(e.target===$('sheetBack')) closeSheet(); };
document.addEventListener('keydown',e=>{ if(e.key==='Escape') closeSheet(); });
$('sheetOk').onclick=()=>{
  const w=$('sheetWord').textContent;
  if($('sheetInput').value.trim()!==w){
    $('sheetInput').style.borderColor='var(--red)'; $('sheetInput').focus(); return;
  }
  closeSheet(); sheetAction&&sheetAction();
};

/* ————— limpeza ————— */
function needCreds(){ if(!$('password').value){ $('password').focus(); return true; } return false; }
async function doClean(file){
  if(needCreds()) return;
  const plan=await api('/api/clean',{report:file});
  if(plan.noop){ seal('ok','Nada a limpar','Este relatório não tem itens acionáveis.'); return; }
  const p=plan.plan||plan;
  const items=(p.to_move||[]).map(f=>`<span class="path">${esc(f.path)}</span>`).join('');
  openSheet('Limpar site',
    'LIMPAR',
    `Será movido para quarentena (reversível) — backup local em <b>wpn_backups/</b>:${items}`+
    (p.restore_index?'<br>· <b>index.php restaurado</b>':'')+
    (p.htaccess&&p.htaccess.length?'<br>· <b>.htaccess regravado</b>':''),
    async()=>{
      seal('busy','Limpando…','Movendo arquivos para a quarentena.');
      $('globalSpin').classList.add('on'); scanning=true; $('btnScan').disabled=true;
      const log=$('scanLog'); log.hidden=false; $('navScan').click();
      const res=await api('/api/clean',{report:file,execute:true,confirm:'LIMPAR',
        host:$('host').value.trim()||p.host,user:$('user').value.trim()||p.user,
        port:$('port').value.trim()||p.port,password:$('password').value});
      if(res.job_id) pollJob(res.job_id, log, j=>{
        scanning=false; $('btnScan').disabled=false;
        if(j.status==='done'){ seal('ok','Limpeza concluída','Aguarde a próxima auditoria e confirme.'); }
        lastReportRefresh();
      });
      else { seal('bad','Erro na limpeza',JSON.stringify(res).slice(0,90));
             scanning=false; $('btnScan').disabled=false; $('globalSpin').classList.remove('on'); }
    }, true);
}
function lastReportRefresh(){ if(lastReport) openFindings(lastReport); }

/* ————— salts ————— */
function doSalts(){
  if(needCreds()) return;
  const host=$('host').value.trim(), user=$('user').value.trim(), port=$('port').value.trim()||21;
  openSheet('Rotacionar salts','SALTS',
    'Regrava <b>wp-config.php</b> com 8 chaves novas. Todas as sessões logadas (incluindo a de um invasor) são encerradas.',
    async()=>{
      seal('busy','Rotacionando salts…','Regravando wp-config.php.');
      $('globalSpin').classList.add('on');
      const log=$('scanLog'); log.hidden=false; $('navScan').click();
      const res=await api('/api/salts',{report:lastReport||'',confirm:'SALTS',host,user,port,password:$('password').value});
      if(res.job_id) pollJob(res.job_id, log, j=>{
        $('navScan').click();
        j.status==='done'?seal('ok','Salts atualizadas','Todas as sessões foram invalidadas.'):
                          seal('bad','Erro na rotação',j.error||'');
      });
      else seal('bad','Erro','precisa de um relatório aberto');
    }, true);
}
$('navSalts').onclick=doSalts;

/* ————— banco de dados ————— */
function doDb(mode){
  const domain=$('domain').value.trim();
  if(!domain){ $('domain').focus(); $('navScan').click(); return; }
  if(needCreds()) return;
  const exec=mode==='execute';
  const body=`Auditoria: lista usuários, fantasmas e senhas de aplicativo.`+
    (exec?`<br><br>Com <b>execução</b>: exclui usuários-fantasma e redefine senhas de administradores legítimos (senha aleatória, enviada no log).`:``)+
    `<br><br>Domínio: <b>${esc(domain)}</b>`;
  openSheet('Banco de dados', exec?'EXECUTAR':'CONSULTAR', body,
    async()=>{
      seal('busy','Banco de dados…','Abrindo o probe.');
      $('globalSpin').classList.add('on');
      const log=$('scanLog'); log.hidden=false; $('navScan').click();
      const res=await api('/api/db',{host:$('host').value.trim(),user:$('user').value.trim(),
        port:$('port').value.trim()||21,password:$('password').value,domain,execute:exec,resetpass:exec});
      if(res.job_id) pollJob(res.job_id, log, j=>{
        $('navScan').click();
        if(j.status==='done') seal('ok','Banco verificado','Detalhes no log.');
        else seal('bad','Erro no banco',j.error||'');
      });
    }, exec);
}
$('navDb').onclick=()=>doDb('audit');

/* ————— ações pós-scan ————— */
$('btnOpenReport').onclick=()=>{ if(lastReport) openFindings(lastReport); };
$('btnQuickClean').onclick=()=>{ if(lastReport) doClean(lastReport); };

/* init */
renderDatalist(); loadReports(); loadJobs();
setInterval(loadJobs,6000);
</script>
</body></html>"""

class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, code=200):
        data=json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u=urllib.parse.urlparse(self.path)
        if u.path=="/":
            data=PAGE.encode()
            self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.end_headers()
            self.wfile.write(data)
        elif u.path=="/api/jobs":
            self._json(api_list())
        elif u.path=="/api/reports":
            self._json(api_reports_list())
        elif u.path.startswith("/api/job/"):
            self._json(api_job_get(u.path.split("/")[-1]))
        elif u.path.startswith("/report/"):
            fn=os.path.basename(urllib.parse.unquote(u.path.split("/report/")[1]))
            p=os.path.join(REPORTS_DIR,fn)
            if os.path.exists(p):
                ctype="text/html" if fn.endswith(".html") else "application/json"
                data=open(p,"rb").read()
                self.send_response(200); self.send_header("Content-Type",ctype+"; charset=utf-8"); self.end_headers(); self.wfile.write(data)
            else:
                self._json({"error":"não encontrado"},404)
        else:
            self._json({"error":"não encontrado"},404)

    def do_POST(self):
        u=urllib.parse.urlparse(self.path)
        try:
            length=int(self.headers.get("Content-Length",0))
            payload=json.loads(self.rfile.read(length) or b"{}")
        except Exception as e:
            self._json({"error":"payload inválido: %s"%e}); return
        if u.path=="/api/scan":
            self._json(api_scan(payload))
        elif u.path=="/api/clean":
            self._json(api_clean(payload))
        elif u.path=="/api/salts":
            self._json(api_salts(payload))
        elif u.path=="/api/db":
            self._json(api_db(payload))
        else:
            self._json({"error":"não encontrado"},404)

    def log_message(self, fmt,*a):
        return  # silencia log no stdout

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--port",type=int,default=8787)
    a=ap.parse_args()
    srv=ThreadingHTTPServer(("127.0.0.1",a.port),Handler)
    print("wp-nuclear UI em http://localhost:%s  (Ctrl+C para sair)"%a.port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass

if __name__=="__main__":
    main()
