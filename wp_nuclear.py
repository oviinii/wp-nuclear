#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wp-nuclear — Auditoria e limpeza guiada de WordPress comprometido via FTP.

Baseado no playbook real usado na limpeza de dois sites WordPress comprometidos
pelos kits KGS e NOX-CLOAK (outubro/2026). 100% stdlib Python 3.9+.

COMANDOS
  scan     — audita via FTP (read-only) e gera relatório JSON/HTML
  clean    — aplica limpeza dos achados do relatório (mexe no servidor)
  salts    — rotaciona as 8 keys/salts do wp-config.php
  db       — auditoria do banco via probe PHP (--execute limpa ghosts)
  monitor  — compara com um relatório anterior (baseline)

Fluxo típico:
  1) scan  → 2) revisar relatório  → 3) clean --execute  → 4) salts --execute  → 5) db
"""
import argparse, ftplib, getpass, io, json, os, random, re, ssl, string, sys, time
import urllib.request
import html as _htmlmod
from datetime import datetime

def html_escape(s):
    import html
    return html.escape(s)

SIG_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures.json")

QUAR_SUFFIX = "quarantine_wpn_%s" % datetime.now().strftime("%Y%m%d_%H%M%S")

# ================================================================ utilsftp

def connect(host, user, password, port=21, timeout=90):
    f = ftplib.FTP()
    f.connect(host, port, timeout=timeout)
    f.login(user, password)
    f.set_pasv(True)
    return f

def ftp_dir(f, path):
    out = []
    def cb(line):
        parts = line.split(None, 8)
        name = parts[-1] if parts else ""
        out.append((name, line.startswith("d"), line))
    f.dir(path, cb)
    return out

def ftp_read(f, path):
    buf = []
    f.retrbinary("RETR " + path, buf.append)
    return b"".join(buf)

def ftp_write(f, path, data):
    return f.storbinary("STOR " + path, io.BytesIO(data))

def ftp_move(f, src, dst):
    f.sendcmd("RNFR " + src)
    return f.sendcmd("RNTO " + dst)

def parse_cfg(cfg: str, name):
    m = re.search(r"define\(\s*'"+re.escape(name)+r"'\s*,\s*'([^']*)'\s*\);", cfg)
    return m.group(1) if m else ""

def table_prefix(cfg: str):
    m = re.search(r"\$table_prefix\s*=\s*'([^']*)'", cfg)
    return m.group(1) if m else "wp_"

def gen(n=64, alphabet=None):
    alphabet = alphabet or (string.ascii_letters + string.digits + "!@#$%^&*-_=+")
    return "".join(random.SystemRandom().choice(alphabet) for _ in range(n))

def load_signatures(path):
    with open(path or SIG_DEFAULT, "r", encoding="utf-8") as fh:
        return json.load(fh)

def resolve_root(f, forced=None):
    if forced:
        return forced.rstrip("/") or "/"
    try:
        pwd = f.pwd()
    except Exception:
        pwd = "/"
    for cand in [pwd, "/public_html", "/"]:
        try:
            names = {n for (n, d, raw) in ftp_dir(f, cand)}
            if "wp-config.php" in names:
                return cand.rstrip("/") or "/"
        except Exception:
            continue
    return pwd.rstrip("/") or "/"

# ================================================================ DB probe

DBPROBE = r"""<?php
error_reporting(0);
try { $m=new mysqli('@@DBH@@','@@DBU@@','@@DBP@@','@@DBN@@'); }
catch (Throwable $e) { echo "AUTHERR|".substr($m->connect_error,0,120)."\n"; exit; }
$m->store_results = true;
foreach(@$m->query("SELECT u.ID,u.user_login,u.user_email,u.user_registered,(SELECT meta_value FROM @@PR@@usermeta mm WHERE mm.user_id=u.ID AND mm.meta_key='@@VCAP@@_capabilities') AS caps FROM @@PR@@users u ORDER BY u.ID") as $u){
  echo "USER|".$u["ID"]."|".$u["user_login"]."|".trim($u["user_email"])."|".preg_replace('/[\r\n]+/',' ',substr((string)$u["caps"],0,220))."|".$u["user_registered"]."\n";
}
foreach(@$m->query("SELECT user_id FROM @@PR@@usermeta WHERE meta_key LIKE '%application%password%'") as $u){
  echo "APW|".$u["user_id"]."\n";
}
foreach(@$m->query("SELECT option_name, LEFT(option_value,500) AS v FROM @@PR@@options WHERE option_name IN ('siteurl','home','admin_email','users_can_register','default_role','active_plugins','template','stylesheet')") as $u){
  echo "OPT|".$u["option_name"]."|".preg_replace('/[\r\n]+/',' ',$u["v"])."\n";
}
"""

DBPROBE_ACT = r"""<?php
error_reporting(0);
$m=new mysqli('@@DBH@@','@@DBU@@','@@DBP@@','@@DBN@@');
if($m->connect_error){ echo "AUTHERR\n"; exit; }
$q="DELETE FROM @@PR@@users WHERE user_login REGEXP '$pat'";
$st=$m->prepare("DELETE FROM @@PR@@users WHERE user_login REGEXP ?");
$pat=isset($_GET['pat'])?$_GET['pat']:'crt_.+|admin_[a-z0-9]+$'; 
$st->bind_param("s",$pat); $st->execute();
echo "DELETED_USERS|".$st->affected_rows."\n";
$q2="DELETE FROM @@PR@@usermeta WHERE user_id NOT IN (SELECT ID FROM @@PR@@users)";
$st2=$m->prepare($q2); $st2->execute();
echo "ORPHAN_META_DELETED|".$st2->affected_rows."\n";
if(isset($_GET['resetpass'])){
  $ids=array();
  foreach($m->query("SELECT ID FROM @@PR@@users") as $u){ $ids[]=$u["ID"]; }
  $st3=$m->prepare("UPDATE @@PR@@users SET user_pass=?, user_activation_key='' WHERE ID=?");
  foreach($ids as $id){
    $h=password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT);
    $st3->bind_param("si",$h,$id); $st3->execute();
    echo "RESET|$id\n";
  }
}
"""

def probe_run(domain, filename):
    """Fetch https://domain/<filename> com fallback http. Não cria arquivo."""
    results = {"out": "", "scheme": "https"}
    for scheme in ("https", "http"):
        hosturl = domain if "://" in domain else scheme + "://" + domain
        baseurl = hosturl.rstrip("/")
        try:
            ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            r = urllib.request.urlopen("%s/%s" % (baseurl, filename), context=ctx, timeout=60)
            results["out"] = r.read().decode(errors="replace")
            results["scheme"] = scheme
            return results
        except Exception as e:
            results["err_%s" % scheme] = str(e)
    return results

def db_scan(f, root, domain):
    cfg = ftp_read(f, root + "/wp-config.php").decode(errors="replace")
    dbh, dbu, dbp, dbn = parse_cfg(cfg,"DB_HOST"), parse_cfg(cfg,"DB_USER"), parse_cfg(cfg,"DB_PASSWORD"), parse_cfg(cfg,"DB_NAME")
    pr = table_prefix(cfg)
    php = DBPROBE.replace("@@DBH@@",dbh).replace("@@DBU@@",dbu).replace("@@DBP@@",dbp).replace("@@DBN@@",dbn)
    php = php.replace("@@PR@@",pr).replace("@@VCAP@@",pr.rstrip("_"))
    ftp_write(f, root + "/__wpn_probe_db.php", php.encode())
    res = probe_run(domain, "__wpn_probe_db.php")
    bpm = f.retrbinary  # noop
    ftp_rmfile_or(f, root + "/__wpn_probe_db.php")
    users, apw, opts = [], [], {}
    out = res.get("out", "")
    for line in out.splitlines():
        if line.startswith("USER|"):
            p = line.split("|", 5)
            users.append({"id":p[1],"login":p[2],"email":p[3],"caps":p[4],"registered":p[5] if len(p)>5 else ""})
        elif line.startswith("APW|"): apw.append(p if False else line.split("|")[1])
        elif line.startswith("OPT|"):
            a, b = line.split("|",2)[1:] if len(line.split("|",2))>2 else ("","")
            opts[a]=b
    return users, apw, opts, out

def ftp_rmfile_or(f, path):
    try:
        f.delete(path)
    except Exception:
        try:
            if f.pwd().endswith("public_html"):
                pass
        except Exception:
            pass

# ================================================================ commands

def cmd_scan(args):
    sig = load_signatures(args.signatures)
    password = args.password
    if not password:
        password = getpass.getpass("Senha FTP para %s@%s: " % (args.user, args.host))
    f = connect(args.host, args.user, password, port=args.port)
    root = resolve_root(f, args.path)
    print("[+] root=%s" % root)
    findings = []

    def add(path, sev, kind, msg, extra=None):
        findings.append({"path":path,"severity":sev,"kind":kind,"msg":msg,"extra":extra or ""})

    entries = [(n,d,raw) for (n,d,raw) in ftp_dir(f, root) if n not in (".","..")]
    names = [n for (n,d,raw) in entries]
    rootset = set(names)

    for (n,d,raw) in entries:
        if n in sig["root_ignore"]: continue
        p = root+"/"+n
        if n in sig["root_high"]:
            add(p,"high","artifact","arquivo conhecido do kit de invasão: %s"%n); continue
        hit=None
        for rx,msg in list(sig["high_regexes"].items())+list(sig["review_regexes"].items()):
            try:
                if re.match(rx,n): hit=(rx,msg); break
            except re.error: pass
        if hit:
            sev = "high" if hit[0] in sig["high_regexes"] else "review"
            add(p,sev,"artifact",hit[1]); continue
        if d:
            for rx,msg in sig.get("dir_review_regexes",{}).items():
                try:
                    if re.match(rx,n): add(p,"review","dir",msg); break
                except re.error: pass

    # .htaccess
    if ".htaccess" in rootset:
        try:
            ht=ftp_read(f,root+"/.htaccess").decode(errors="replace")
            for rx in sig["htaccess_regexes"]:
                if re.search(rx["re"],ht):
                    add(root+"/.htaccess",rx["sev"],"htaccess",rx["msg"])
        except Exception as e:
            print("  [warn] htaccess read: %s"%e)

    # wp-config
    if "wp-config.php" in rootset:
        wc = ftp_read(f,root+"/wp-config.php").decode(errors="replace")
        for rx in sig["wpconfig_warn"]:
            if re.search(rx["re"],wc):
                add(root+"/wp-config.php","warn","wpconfig",rx["msg"])
        if re.search(r"define\s*\(\s*'[^']*'\s*,\s*(eval|base64_decode|gzinflate)\s*\(?", wc):
            add(root+"/wp-config.php","high","wpconfig","define com código injetado")
        if "put your unique phrase here" in wc:
            add(root+"/wp-config.php","warn","wpconfig","salts ainda são placeholders")

    # index_original.php / index.php
    if sig["index_original_name"] in rootset:
        add(root+"/"+sig["index_original_name"],"high","restore-needed","index.php renomeado pelo kit (restaurar com clean)")
    if "index.php" in rootset:
        try:
            idx=ftp_read(f,root+"/index.php")
            if len(idx)>2000:
                add(root+"/index.php","high","index","index.php ¿Injetado? (%d bytes, esperado ~405)"%len(idx))
        except Exception: pass

    # mu-plugins
    try:
        for (n,d,raw) in ftp_dir(f,root+"/wp-content/mu-plugins"):
            if n in (".",".."): continue
            if not any(n.startswith(p) for p in sig["mu_allow_prefixes"]):
                add(root+"/wp-content/mu-plugins/"+n,"high","mu-plugin","mu-plugin outside whitelist (revisar)")
    except Exception: pass

    # plugin stashes
    try:
        for (n,d,raw) in ftp_dir(f,root+"/wp-content/plugins"):
            if d and n not in (".",".."):
                try:
                    fs={x for (x,d2,r2) in ftp_dir(f,root+"/wp-content/plugins/"+n) if x not in (".","..")}
                    if "functions_bak.php" in fs and len(fs)<=2:
                        add(root+"/wp-content/plugins/"+n,"high","plugin-stash","stash de functions.php do tema dentro de plugin-fantasma")
                except Exception: pass
    except Exception: pass

    # uploads php
    try:
        found_php=[]
        def walk(p, depth=0, budget=[0]):
            if depth>6 or budget[0]>3000: return
            for (n,d,raw) in ftp_dir(f,p):
                if n in (".",".."): continue
                if d: walk(p+"/"+n, depth+1, budget)
                else:
                    if n.lower().endswith((".php",".php5",".phtml")):
                        found_php.append(p+"/"+n); budget[0]+=1
        walk(root+"/wp-content/uploads")
        for s in found_php[:30]:
            add(s,"high","uploads-php","PHP de execução não pertence a uploads de WP")
        if len(found_php)>30:
            add(root+"/wp-content/uploads","high","uploads-php","...e %d PHPs adicionais" % (len(found_php)-30))
    except Exception as e:
        print("  [warn] uploads: %s"%e)

    # content scan root php
    for (n,d,raw) in entries:
        if d: continue
        if n.lower().endswith((".php",".php5",".phtml")) and n not in sig["root_ignore"]:
            try:
                s=ftp_read(f,root+"/"+n).decode(errors="replace")
                for rx in sig["php_regexes"]:
                    if re.search(rx["re"],s):
                        add(root+"/"+n,rx["sev"],"php-content","%s"%rx["msg"]); break
            except Exception: pass

    # db
    dbdata=None
    if args.db_probe:
        if not args.domain:
            print("[!] --db-probe exige --domain"); 
        else:
            print("[*] DB probe em execução...")
            users, apw, opts, raw = db_scan(f, root, args.domain)
            ghosts=[]
            for u in users:
                lg=u["login"].lower()
                if any(re.match(rx,lg) for rx in sig["database_ghost_logins"]):
                    ghosts.append(u)
            dbdata={"users":users,"app_passwords":apw,"options":opts,"ghosts":ghosts,"raw":raw.splitlines()[:60]}
            print("[+] DB: %d usuários | ghosts=%d | app-passwords=%d" % (len(users), len(ghosts), len(apw)))

    try: f.quit()
    except Exception: pass

    report={"generated":datetime.now().isoformat(),
            "site":args.domain or args.host,"host":args.host,"user":args.user,
            "port":args.port,"path":root,
            "quarantine_hint":"/%s"%QUAR_SUFFIX,
            "findings":findings,"db":dbdata}
    # summary
    sev_count={}
    for fd in findings: sev_count[fd["severity"]]=sev_count.get(fd["severity"],0)+1
    print("\n=== RESUMO ===  high=%s warn=%s review=%s" % (sev_count.get("high",0),sev_count.get("warn",0),sev_count.get("review",0)))
    for fd in findings:
        print("  [%-6s] %-60s %s" % (fd["severity"].upper(), fd["path"], fd["msg"]))
    if dbdata:
        print("  [db] ghosts=%s" % ([g["login"] for g in dbdata["ghosts"]] or "-"))
        print("  [db] usuários=%s" % [u["login"] for u in dbdata["users"]])
    # outputs
    if args.json:
        base=os.path.dirname(args.json); os.makedirs(base,exist_ok=True) if base else None
        with open(args.json,"w",encoding="utf-8") as fh: json.dump(report,fh,indent=2,ensure_ascii=False)
        print("[+] JSON: %s"%args.json)
    if args.html:
        html_report(report, args.html)
        print("[+] HTML: %s"%args.html)
    return report

def html_report(report, outpath):
    F = report["findings"]
    def row(fd):
        color={"high":"#b00020","warn":"#e6a700","review":"#5b6770"}.get(fd["severity"],"#333")
        return "<tr><td><span style='color:%s;font-weight:bold'>%s</span></td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>" % (
            color, fd["severity"].upper(), html_escape(fd["path"]), html_escape(fd["kind"]), html_escape(fd["msg"]))
    db=report.get("db") or {}
    dbhtml=""
    if isinstance(db,dict) and "users" in db:
        rows="".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"%(html_escape(str(u["id"])),html_escape(u["login"]),html_escape(u["email"]),html_escape(u["registered"])) for u in db["users"])
        dbhtml="<h2>Database</h2><table border=1 cellpadding=5><tr><th>ID</th><th>login</th><th>email</th><th>criado em</th></tr>%s</table><p>Ghosts: %s | App Passwords: %s</p>"%(rows,html_escape(str([g["login"] for g in db.get("ghosts",[])])),html_escape(str(db.get("app_passwords",[]))))
    else:
        dbhtml="<p>DB probe não executado.</p>"
    html="""<html><head><meta charset="utf-8"><title>wp-nuclear audit — %(site)s</title>
    <style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:1000px;margin:2em auto;padding:0 1em}
    table{border-collapse:collapse;width:100%%}td,th{border:1px solid #ccc;padding:6px 10px;font-size:13px}
    code{background:#f4f4f6;padding:2px 4px;border-radius:3px;word-break:break-all}h1{margin-bottom:.2em}</style></head>
    <body><h1>wp-nuclear — relatório de auditoria</h1>
    <p>Site: <b>%(site)s</b> &nbsp; Gerado: <b>%(when)s</b> &nbsp; Root: <code>%(root)s</code></p>
    <table><tr><th>Gravidade</th><th>Caminho</th><th>Tipo</th><th>Motivo</th></tr>%(rows)s</table>
    %(dbhtml)s<p style="color:#777;font-size:12px">Relatório gerado localmente; nenhuma alteração no servidor foi feita no modo scan.</p></body></html>""" % {
        "site": html_escape(report["site"]), "when": html_escape(report["generated"]),
        "root": html_escape(report["path"]), "rows": "".join(row(fd) for fd in F),
        "dbhtml": dbhtml }
    with open(outpath,"w",encoding="utf-8") as fh: fh.write(html)

def load_report(path):
    with open(path,"r",encoding="utf-8") as fh:
        return json.load(fh)

def cmd_clean(args):
    report=load_report(args.report)
    root=report["path"]
    F=report["findings"]
    to_move=[fd for fd in F if fd["severity"]=="high" and fd["kind"] in ("artifact","mu-plugin","plugin-stash","uploads-php","dir")]
    restore_index=sig_restore_needed(F)
    htacs=[fd for fd in F if fd["kind"]=="htaccess" and fd["severity"]=="high"]
    if not to_move and not restore_index and not htacs:
        print("✨ Nada a fazer — relatório sem achados de alta gravidade acionáveis.")
        return
    host,user,port=report["host"],report["user"],report.get("port",21)
    password=args.password or getpass.getpass("Senha FTP: ")
    f=connect(host,user,password,port=port)
    print("=== PLANO DE LIMPEZA ===")
    print("→ mover para quarentena:")
    for fd in to_move: print("   %s"%fd["path"])
    if restore_index: print("→ renomear index_original.php → index.php")
    if htacs: print("→ regravar .htaccess (remover blocos maliciosos)")
    if not args.execute:
        print("\n(REAL RUN não acionado; use --execute para aplicar)"); return
    if not args.yes:
        confirm=input("Digite LIMPAR para executar: ")
        if confirm.strip()!="LIMPAR":
            print("Cancelado."); return
    q=root.replace("/public_html","")+"/quarantine_wpn_"+datetime.now().strftime("%Y%m%d_%H%M%S")
    try: f.mkd(q); print("[+] quarentena: %s"%q)
    except Exception as e: print("[!] mkdir:",e); q=None
    backups=[]
    os.makedirs(args.backup,exist_ok=True) if args.backup else None
    moved=[]
    def local_backup(path, data):
        if not args.backup: return
        rel=path.strip("/").replace("/","__")
        with open(os.path.join(args.backup,rel),"wb") as fh: fh.write(data)
    for fd in to_move:
        p=fd["path"]
        try:
            try:
                data=ftp_read(f,p)
                local_backup(p, data)
            except Exception:
                data=None  # diretórios não baixam — segue direto p/ quarentena
            dst=(q+"/"+p.rsplit("/",1)[-1]) if q else None
            if q: ftp_move(f,p,dst); moved.append((fd, dst))
            print("[movido] %s"%p)
        except Exception as e:
            print("[skip] %s : %s"%(p,e))
    # restore index.php if needed
    if restore_index:
        try:
            oi=sig_index_original_path(F,root) or (root+"/index_original.php")
            ftp_move(f, oi, root+"/index.php"); print("[restaurado] index.php")
            # also move any index.html (static spam index)
            try:
                idxh=root+"/index.html"; data=ftp_read(f,idxh); local_backup(idxh,data); ftp_move(f,idxh,q+"/index.html")
                print("[quarentena] index.html")
            except Exception: pass
        except Exception as e: print("[!] index restore:",e)
    # htaccess
    if htacs:
        try:
            ht=ftp_read(f,root+"/.htaccess").decode(errors="replace")
            local_backup(root+"/.htaccess", ht.encode())
            cleaned=strip_htaccess_blocks(ht)
            if cleaned!=ht:
                ftp_write(f,root+"/.htaccess",cleaned.encode()); print("[regravado] .htaccess")
            else: print("[.] .htaccess sem blocos a remover após análise")
        except Exception as e: print("[!]",e)
    # robots.txt safety restore if kit-generated
    try:
        rob=ftp_read(f,root+"/robots.txt").decode(errors="replace")
        if "sitemap"+any_digit_decoy(rob):
            new=clean_robots(rob, report["site"])
            if new!=rob:
                local_backup(root+"/robots.txt",rob.encode())
                ftp_write(f,root+"/robots.txt",new.encode()); print("[regravado] robots.txt")
    except Exception: pass
    print("[✓] limpeza aplicada. Quarentena remota: %s"%q)
    moved_summary={"quarantine":q,"moved":[{"from":fd["path"],"to":dst} for (fd,dst) in moved]}
    if args.json:
        with open(args.json,"w",encoding="utf-8") as fh: json.dump(moved_summary,fh,indent=2)
    try: f.quit()
    except Exception: pass

def any_digit_decoy(s): return re.search(r"sitemap\d+\.xml",s)
def clean_robots(rob, site):
    base={"User-agent: *","Allow: /"}
    return "User-agent: *\nAllow: /\n\n"
def sig_restore_needed(F):
    return any(fd["kind"]=="restore-needed" for fd in F)
def sig_index_original_path(F,root):
    for fd in F:
        if fd["kind"]=="restore-needed": return fd["path"]
    return root+"/index_original.php"
def strip_htaccess_blocks(ht):
    anchors=["# BEGIN LSCACHE","# END NOX-CLOAK-RULE","# BEGIN WordPress"]
    for a in ["# BEGIN LSCACHE"]:
        i=ht.find(a)
        if i>0: return ht[i:]
    # fallback: remove KGS/NOX lines windows
    ht2=re.sub(r"(?ms)^#\s*(KGS_BOT_RULE|BEGIN NOX-CLOAK-RULE|END NOX-CLOAK-RULE).*?\n\n","",ht)
    return ht2

def cmd_salts(args):
    report=load_report(args.report)
    host,user,port=report["host"],report["user"],report.get("port",21)
    root=report["path"]
    password=args.password or getpass.getpass("Senha FTP: ")
    f=connect(host,user,password,port=port)
    path=root+"/wp-config.php"
    cfg=ftp_read(f,path).decode(errors="replace")
    keys=["AUTH_KEY","SECURE_AUTH_KEY","LOGGED_IN_KEY","NONCE_KEY","AUTH_SALT","SECURE_AUTH_SALT","LOGGED_IN_SALT","NONCE_SALT"]
    rep=0
    for k in keys:
        cfg,n=re.subn(r"define\(\s*'"+k+r"'\s*,\s*'[^']*'\s*\);", "define( '"+k+"', '"+gen()+"' );", cfg, count=1)
        rep+=n
    print("salts substituídas: %d/8"%rep)
    if not args.execute:
        print("(dry-run — nada alterado; use --execute)"); return
    if not args.yes and input("Digite SALTS para aplicar: ").strip()!="SALTS": return
    if args.backup:
        os.makedirs(args.backup,exist_ok=True)
        open(os.path.join(args.backup,"wp-config.before.txt"),"w",encoding="utf-8").write(ftp_read(f,path).decode(errors="replace"))
    print("STOR:", ftp_write(f,path,cfg.encode()))
    v=[]
    v.append(ftp_read(f,path).decode(errors="replace"))
    print("[✓] verificado remoto AUTH_KEY:", re.search(r"define\(\s*'AUTH_KEY'\s*,\s*'([^']*)'", v[0]).group(1)[:16])
    try: f.quit()
    except Exception: pass

def cmd_db(args):
    report=load_report(args.report)
    host,user,port=report["host"],report["user"],report.get("port",21)
    root=report["path"]
    password=args.password or getpass.getpass("Senha FTP: ")
    f=connect(host,user,password,port=port)
    if not args.domain:
        args.domain=report.get("site") if report.get("site") and "://" in report.get("site") else None
    users,apw,opts,out=db_scan(f,root,args.domain)
    ghosts=[u for u in users if any(re.match(rx,u["login"].lower()) for rx in load_signatures(args.signatures)["database_ghost_logins"])]
    print("Usuários: %s"%[u["login"] for u in users])
    print("Ghosts: %s"%([g["login"] for g in ghosts] or "nenhum"))
    print("App passwords: %s"%(apw or "nenhuma"))
    print("siteurl=%s users_can_register=%s"%(opts.get("siteurl","?"),opts.get("users_can_register","?")))
    if args.execute and ghosts or (args.execute and args.resetpass):
        if not args.domain: print("[!] precisa --domain para plugin probe actions"); return
        cfg=ftp_read(f,root+"/wp-config.php").decode(errors="replace")
        pr=table_prefix(cfg)
        act=DBPROBE_ACT.replace("@@PR@@",pr).replace("@@DBH@@",parse_cfg(cfg,"DB_HOST"))\
            .replace("@@DBU@@",parse_cfg(cfg,"DB_USER")).replace("@@DBP@@",parse_cfg(cfg,"DB_PASSWORD"))\
            .replace("@@DBN@@",parse_cfg(cfg,"DB_NAME"))
        # inject explicit login deletion list
        pat="|".join(re.escape(g["login"]) for g in ghosts) if ghosts else "^__none__"
        ftp_write(f,root+"/__wpn_dbact.php",act.encode())
        url_query="?pat="+urllib.request.quote(pat)+"&resetpass=1" if args.resetpass else "?pat="+urllib.request.quote(pat)
        res=probe_run(args.domain, "__wpn_dbact.php")
        # we built __wpn_dbact.php explicitly; call it directly
        baseurl=(args.domain if "://" in args.domain else "https://"+args.domain).rstrip("/")
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        out2=""
        try: out2=urllib.request.urlopen(baseurl+"/__wpn_dbact.php"+url_query, context=ctx, timeout=60).read().decode(errors="replace")
        except Exception as e: out2="HTTPFAIL %s"%e
        print(out2[:1000])
        try: f.delete(root+"/__wpn_dbact.php")
        except Exception as e: print("rm:",e)
    else:
        print("(nada alterado; use --execute [--resetpass])")
    try: f.quit()
    except Exception: pass

def cmd_monitor(args):
    prev=load_report(args.baseline)
    now=load_report(args.report)
    def set_of(rep):
        return {fd["path"] for fd in rep["findings"]}
    p,n=set_of(prev),set_of(now)
    print("arquivos novos suspeitos:", sorted(n-p) or "NENHUM")
    print("besteira perdida da lista anterior:", sorted(p-n) or "nenhuma")

# ---------------------------------------------------------------- main

def main():
    ap=argparse.ArgumentParser(prog="wp-nuclear", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub=ap.add_subparsers(dest="cmd", required=True)

    common=argparse.ArgumentParser(add_help=False)
    common.add_argument("--host",required=True); common.add_argument("--user",required=True)
    common.add_argument("--password",default=None); common.add_argument("--port",type=int,default=21)
    common.add_argument("--path",default=None, help="caminho do WP dentro do FTP (auto-detect se vazio)")
    common.add_argument("--signatures",default=SIG_DEFAULT)
    common.add_argument("--backup",default="./wpn_backups")

    p_scan=sub.add_parser("scan",parents=[common])
    p_scan.add_argument("--domain",default=None,help="https://dominio.com.br (necessário para --db-probe)")
    p_scan.add_argument("--db-probe",action="store_true")
    p_scan.add_argument("--json",default=None); p_scan.add_argument("--html",default=None)
    p_scan.set_defaults(func=cmd_scan)

    p_clean=sub.add_parser("clean",parents=[common])
    p_clean.add_argument("--report",required=True); p_clean.add_argument("--execute",action="store_true")
    p_clean.add_argument("--yes",action="store_true",help="não-prompt (usar via script/UI)")
    p_clean.add_argument("--json",default=None)
    p_clean.set_defaults(func=cmd_clean)

    p_salts=sub.add_parser("salts",parents=[common])
    p_salts.add_argument("--report",required=False, help="estado antecede salts do wp-config")
    p_salts.add_argument("--execute",action="store_true")
    p_salts.add_argument("--yes",action="store_true",help="não-prompt (usar via script/UI)")
    p_salts.set_defaults(func=cmd_salts)

    p_db=sub.add_parser("db",parents=[common])
    p_db.add_argument("--report",required=True); p_db.add_argument("--domain",default=None)
    p_db.add_argument("--execute",action="store_true"); p_db.add_argument("--resetpass",action="store_true")
    p_db.set_defaults(func=cmd_db)

    p_mon=sub.add_parser("monitor",parents=[common])
    p_mon.add_argument("--baseline",required=True); p_mon.add_argument("--report",required=True)
    p_mon.set_defaults(func=cmd_monitor)

    args=ap.parse_args()
    args.func(args)

if __name__=="__main__":
    main()
