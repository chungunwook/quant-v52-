"""
═══════════════════════════════════════════════════════════════════════
  매일 투자 추천 V5.2 — 프록시 서버
  ───────────────────────────────────────────────────────────────────────
  역할:
    1) 키움 REST API 중계 (브라우저 CORS 우회)
    2) 네이버 금융 실시간 시세 파싱 (100% 팩트 데이터 수집)
    3) V5.2 퀀트 통합 로직 — 노이즈 지수 & Cpk 기반 2종목 자동 추출

  실행 방법:
    pip install flask flask-cors requests beautifulsoup4 lxml
    python proxy_server.py
    → http://localhost:8000 접속

  ※ 키움 API 키 없이도 '네이버 금융 모드'로 완전 동작합니다.
═══════════════════════════════════════════════════════════════════════
"""

from flask import Flask, request, jsonify, send_from_directory, redirect, make_response, render_template_string
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import re
import time
import os
import json
import secrets
import hashlib
import threading
from datetime import datetime, timedelta

app = Flask(__name__, static_folder='.')
CORS(app)

# 실전 기록장 저장 경로 (스크립트와 같은 폴더)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
JOURNAL_PATH = os.path.join(SCRIPT_DIR, "journal.json")
CONFIG_PATH  = os.path.join(SCRIPT_DIR, "config.json")
_journal_lock = threading.Lock()

# ───────────────────────────────────────────────────────────────────────
#  접속 비밀번호 (선택 기능)
# ───────────────────────────────────────────────────────────────────────
#  ENABLE_PIN_AUTH=True 일 때만 PIN 인증 활성화. 기본은 꺼짐.
#  - 켜기:  Render 환경변수에 ENABLE_PIN_AUTH=1 추가, 또는 아래 값을 True 로
#  - 활성화 시: 최초 실행 때 4자리 PIN 자동 생성하여 콘솔/로그에 출력
#  - 활성화 시: 폰에서 처음 접속하면 PIN 입력, 한 번 입력 후 30일 자동 로그인
# ───────────────────────────────────────────────────────────────────────
ENABLE_PIN_AUTH = os.environ.get("ENABLE_PIN_AUTH", "").lower() in ("1","true","yes","on")
ALLOW_LOCAL_NO_AUTH = True   # PC 본인(localhost) 접속은 비번 없이 허용

def _load_config():
    if not os.path.exists(CONFIG_PATH):
        # 최초 실행 — 4자리 PIN 자동 생성
        pin = str(secrets.randbelow(10000)).zfill(4)
        cfg = {"access_pin": pin, "session_tokens": []}
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        print("\n" + "=" * 65)
        print(f"  🔐 외부 접속 PIN 생성됨:  {pin}")
        print(f"  (config.json 에 저장. 폰에서 처음 접속 시 입력)")
        print("=" * 65 + "\n")
        return cfg
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"access_pin": "0000", "session_tokens": []}

def _save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

_config_lock = threading.Lock()

def _issue_token():
    """30일 유효 세션 토큰 발급"""
    with _config_lock:
        cfg = _load_config()
        token = secrets.token_urlsafe(24)
        expires = (datetime.now() + timedelta(days=30)).isoformat()
        if "session_tokens" not in cfg:
            cfg["session_tokens"] = []
        cfg["session_tokens"].append({"token": token, "expires": expires})
        # 만료된 토큰 정리
        now = datetime.now()
        cfg["session_tokens"] = [
            t for t in cfg["session_tokens"]
            if datetime.fromisoformat(t["expires"]) > now
        ]
        _save_config(cfg)
    return token

def _is_authenticated():
    """현재 요청이 인증되었는지 검사"""
    # PIN 인증이 꺼져 있으면 항상 통과
    if not ENABLE_PIN_AUTH:
        return True
    # 로컬 접속은 통과 (PC 본인)
    if ALLOW_LOCAL_NO_AUTH:
        remote = request.remote_addr or ""
        if remote.startswith("127.") or remote == "::1" or remote == "localhost":
            return True
    # 세션 토큰 검사
    token = request.cookies.get("session") or request.headers.get("X-Session")
    if not token:
        return False
    cfg = _load_config()
    now = datetime.now()
    for t in cfg.get("session_tokens", []):
        if t["token"] == token:
            try:
                if datetime.fromisoformat(t["expires"]) > now:
                    return True
            except Exception:
                pass
    return False

# Flask 글로벌 인증 검사 (정적 + API)
PUBLIC_PATHS = {"/login", "/api/login", "/health", "/favicon.ico"}

@app.before_request
def _check_auth():
    path = request.path
    if path in PUBLIC_PATHS:
        return None
    if _is_authenticated():
        return None
    # 정적 페이지 → 로그인 페이지로
    if request.method == "GET" and (path == "/" or path.endswith(".html")):
        return redirect("/login")
    # API → 401
    return jsonify({"ok": False, "error": "인증이 필요합니다.", "needLogin": True}), 401


LOGIN_PAGE = """<!DOCTYPE html>
<html lang="ko"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>로그인 — V5.2</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#08090d;color:#e8eaf0;font-family:-apple-system,'Noto Sans KR',sans-serif;
    min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
  .box{background:#141720;border:1px solid #1e2230;border-radius:16px;padding:32px;
    max-width:360px;width:100%;text-align:center}
  .icon{width:48px;height:48px;background:linear-gradient(135deg,#00e5ff,#0077ff);
    border-radius:12px;display:inline-flex;align-items:center;justify-content:center;
    font-size:22px;margin-bottom:16px;box-shadow:0 0 24px rgba(0,229,255,.35)}
  h1{font-size:18px;font-weight:700;margin-bottom:6px}
  .sub{font-size:12px;color:#5a6070;margin-bottom:24px;line-height:1.5}
  input{width:100%;background:#0f1117;border:1px solid #1e2230;border-radius:10px;
    padding:14px;color:#e8eaf0;font-family:'JetBrains Mono',monospace;font-size:24px;
    text-align:center;letter-spacing:8px;outline:none;margin-bottom:14px}
  input:focus{border-color:#00e5ff;box-shadow:0 0 0 3px rgba(0,229,255,.1)}
  button{width:100%;background:linear-gradient(135deg,#00e5ff,#0077ff);color:#000;
    border:none;border-radius:10px;padding:13px;font-size:14px;font-weight:700;
    cursor:pointer;font-family:'Noto Sans KR',sans-serif}
  .err{color:#ff1744;font-size:12px;margin-top:10px;min-height:18px}
  .hint{font-size:10px;color:#5a6070;margin-top:18px;line-height:1.6}
</style></head><body>
<div class="box">
  <div class="icon">⚙️</div>
  <h1>매일 투자 추천 V5.2</h1>
  <div class="sub">PC에서 실행한 서버에 접속 중<br>4자리 PIN을 입력하세요</div>
  <form id="loginForm" onsubmit="return doLogin(event)">
    <input type="password" id="pin" inputmode="numeric" pattern="[0-9]*" maxlength="4"
      placeholder="••••" autofocus autocomplete="off">
    <button type="submit">로그인</button>
    <div class="err" id="err"></div>
  </form>
  <div class="hint">
    PIN은 PC에서 처음 서버 실행 시 콘솔에 출력됩니다.<br>
    또는 PC 폴더의 <strong>config.json</strong> 파일에서 확인.
  </div>
</div>
<script>
async function doLogin(e){
  e.preventDefault();
  const pin = document.getElementById('pin').value;
  const err = document.getElementById('err');
  err.textContent = '';
  try {
    const r = await fetch('/api/login', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({pin})
    });
    const d = await r.json();
    if (!d.ok) { err.textContent = d.error || 'PIN이 올바르지 않습니다.'; return false; }
    location.href = '/';
  } catch (ex) { err.textContent = '서버 오류'; }
  return false;
}
</script>
</body></html>"""

@app.route("/login")
def login_page():
    return LOGIN_PAGE

@app.route("/api/login", methods=["POST"])
def api_login():
    try:
        body = request.get_json() or {}
        pin = str(body.get("pin", "")).strip()
        cfg = _load_config()
        if pin != cfg.get("access_pin"):
            return jsonify({"ok": False, "error": "PIN이 올바르지 않습니다."}), 401
        token = _issue_token()
        resp = make_response(jsonify({"ok": True}))
        # 30일짜리 HttpOnly 쿠키
        resp.set_cookie("session", token, max_age=30*24*3600,
                        httponly=True, samesite="Lax")
        return resp
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route("/api/logout", methods=["POST"])
def api_logout():
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie("session", "", max_age=0)
    return resp

# ───────────────────────────────────────────────────────────────────────
#  설정
# ───────────────────────────────────────────────────────────────────────
KIWOOM_BASE = "https://api.kiwoom.com"          # 실전투자
# KIWOOM_BASE = "https://mockapi.kiwoom.com"    # 모의투자

NAVER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36",
    "Referer": "https://finance.naver.com/",
}

# 토큰 캐시 (메모리)
_token_cache = {"token": None, "expires": 0}


# ═══════════════════════════════════════════════════════════════════════
#  [1] 키움 REST API 중계
# ═══════════════════════════════════════════════════════════════════════
def get_kiwoom_token(app_key, secret_key):
    """접근 토큰 발급 (캐시 사용)"""
    now = time.time()
    if _token_cache["token"] and _token_cache["expires"] > now + 60:
        return _token_cache["token"]

    url = f"{KIWOOM_BASE}/oauth2/token"
    headers = {"Content-Type": "application/json;charset=UTF-8"}
    body = {
        "grant_type": "client_credentials",
        "appkey": app_key,
        "secretkey": secret_key,
    }
    res = requests.post(url, headers=headers, json=body, timeout=10)
    res.raise_for_status()
    data = res.json()
    token = data.get("token")
    if not token:
        raise RuntimeError(f"토큰 발급 실패: {data}")

    _token_cache["token"] = token
    _token_cache["expires"] = now + 3600  # 1시간
    return token


@app.route("/api/kiwoom/token", methods=["POST"])
def kiwoom_token():
    """프론트엔드 → 토큰 발급 요청 중계"""
    try:
        body = request.get_json()
        token = get_kiwoom_token(body["appKey"], body["secretKey"])
        return jsonify({"ok": True, "token": token})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/kiwoom/request", methods=["POST"])
def kiwoom_request():
    """
    키움 REST API 범용 중계
    body: { token, apiId, endpoint, payload }
    """
    try:
        body = request.get_json()
        token = body["token"]
        api_id = body["apiId"]
        endpoint = body["endpoint"]
        payload = body.get("payload", {})

        url = f"{KIWOOM_BASE}{endpoint}"
        headers = {
            "Content-Type": "application/json;charset=UTF-8",
            "Authorization": f"Bearer {token}",
            "api-id": api_id,
        }
        res = requests.post(url, headers=headers, json=payload, timeout=10)
        return jsonify({
            "ok": res.ok,
            "status": res.status_code,
            "data": res.json() if res.content else {},
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# ═══════════════════════════════════════════════════════════════════════
#  [2] 네이버 금융 시세 파싱 — V5.2 1단계: 100% 팩트 데이터 수집
# ═══════════════════════════════════════════════════════════════════════
def _to_int(text):
    """ '1,234' → 1234 """
    if text is None:
        return 0
    cleaned = re.sub(r"[^\d\-]", "", str(text))
    return int(cleaned) if cleaned and cleaned != "-" else 0


def fetch_naver_ohlc(stock_code):
    """
    네이버 금융에서 종목의 당일 + 전일 시세(OHLC) 파싱
    반환: { code, name, open, high, low, close, prevHigh, prevLow, volume, amount }
    """
    # 종목 기본 정보 (현재가, 종목명)
    url_main = f"https://finance.naver.com/item/main.naver?code={stock_code}"
    res = requests.get(url_main, headers=NAVER_HEADERS, timeout=8)
    res.encoding = "euc-kr"
    soup = BeautifulSoup(res.text, "lxml")

    # 종목명
    name_tag = soup.select_one(".wrap_company h2 a")
    name = name_tag.get_text(strip=True) if name_tag else stock_code

    # 당일 시세 표 (오늘 데이터)
    today = {"open": 0, "high": 0, "low": 0, "close": 0, "volume": 0}
    try:
        # 현재가
        no_today = soup.select_one(".no_today .blind")
        today["close"] = _to_int(no_today.get_text()) if no_today else 0

        # 시가/고가/저가 — 종목 시세 표
        table = soup.select("table.no_info td")
        # 구조: 거래량 / 시가 / 고가 / 거래대금 / 전일가 / 저가
        for td in table:
            label = td.select_one(".sptxt")
            value = td.select_one(".blind")
            if not label or not value:
                continue
            lt = label.get_text(strip=True)
            vv = _to_int(value.get_text())
            if "시가" in lt:
                today["open"] = vv
            elif "고가" in lt:
                today["high"] = vv
            elif "저가" in lt:
                today["low"] = vv
            elif "거래량" in lt:
                today["volume"] = vv
    except Exception:
        pass

    # 일별 시세 (전일 고가/저가)
    prev_high, prev_low, prev_volume = 0, 0, 0
    try:
        url_day = f"https://finance.naver.com/item/sise_day.naver?code={stock_code}&page=1"
        res2 = requests.get(url_day, headers=NAVER_HEADERS, timeout=8)
        res2.encoding = "euc-kr"
        soup2 = BeautifulSoup(res2.text, "lxml")
        rows = soup2.select("table.type2 tr")

        day_rows = []
        for row in rows:
            cols = row.select("td")
            if len(cols) < 7:
                continue
            date_txt = cols[0].get_text(strip=True)
            if not re.match(r"\d{4}\.\d{2}\.\d{2}", date_txt):
                continue
            day_rows.append({
                "date": date_txt,
                "close": _to_int(cols[1].get_text()),
                "open": _to_int(cols[3].get_text()),
                "high": _to_int(cols[4].get_text()),
                "low": _to_int(cols[5].get_text()),
                "volume": _to_int(cols[6].get_text()),
            })

        # day_rows[0] = 최근일(=오늘 또는 전일), day_rows[1] = 그 전일
        if len(day_rows) >= 1:
            # 당일 데이터가 main에서 0이면 일별 시세 최신행으로 보강
            latest = day_rows[0]
            if today["open"] == 0:
                today["open"] = latest["open"]
            if today["high"] == 0:
                today["high"] = latest["high"]
            if today["low"] == 0:
                today["low"] = latest["low"]
            if today["close"] == 0:
                today["close"] = latest["close"]
            if today["volume"] == 0:
                today["volume"] = latest["volume"]
        if len(day_rows) >= 2:
            prev = day_rows[1]
            prev_high = prev["high"]
            prev_low = prev["low"]
            prev_volume = prev["volume"]
    except Exception:
        pass

    return {
        "code": stock_code,
        "name": name,
        "open": today["open"],
        "high": today["high"],
        "low": today["low"],
        "close": today["close"],
        "prevHigh": prev_high,
        "prevLow": prev_low,
        "volume": today["volume"],
        "prevVolume": prev_volume,
    }


@app.route("/api/naver/ohlc", methods=["POST"])
def naver_ohlc():
    """단일 종목 시세 파싱"""
    try:
        body = request.get_json()
        code = body["code"]
        data = fetch_naver_ohlc(code)
        return jsonify({"ok": True, "data": data})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/naver/batch", methods=["POST"])
def naver_batch():
    """
    여러 종목 일괄 시세 파싱
    body: { codes: ["005930", "000660", ...] }
    """
    try:
        body = request.get_json()
        codes = body["codes"]
        results = []
        errors = []
        for code in codes:
            try:
                results.append(fetch_naver_ohlc(code))
                time.sleep(0.15)  # 네이버 부하 방지
            except Exception as e:
                errors.append({"code": code, "error": str(e)})
        return jsonify({"ok": True, "data": results, "errors": errors})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# ═══════════════════════════════════════════════════════════════════════
#  [3] 거래량/거래대금 상위 종목 — V5.2 2단계: 주도 테마 필터링
# ═══════════════════════════════════════════════════════════════════════
def fetch_naver_top_amount(market="KOSDAQ", count=30):
    """
    네이버 금융 거래대금 상위 종목 조회
    market: 'KOSPI'=0, 'KOSDAQ'=1
    """
    sosok = "0" if market == "KOSPI" else "1"
    url = f"https://finance.naver.com/sise/sise_quant.naver?sosok={sosok}"
    res = requests.get(url, headers=NAVER_HEADERS, timeout=8)
    res.encoding = "euc-kr"
    soup = BeautifulSoup(res.text, "lxml")

    stocks = []
    rows = soup.select("table.type_2 tr")
    for row in rows:
        link = row.select_one("a.tltle")
        if not link:
            continue
        href = link.get("href", "")
        m = re.search(r"code=(\d{6})", href)
        if not m:
            continue
        code = m.group(1)
        name = link.get_text(strip=True)
        cols = row.select("td")
        # 거래량 컬럼 위치(거래량 상위 페이지): 보통 index 5 부근
        volume = 0
        if len(cols) >= 6:
            volume = _to_int(cols[5].get_text())
        stocks.append({"code": code, "name": name, "volume": volume})
        if len(stocks) >= count:
            break
    return stocks


@app.route("/api/naver/topamount", methods=["POST"])
def naver_top_amount():
    """거래대금/거래량 상위 종목 리스트"""
    try:
        body = request.get_json() or {}
        market = body.get("market", "KOSDAQ")
        count = body.get("count", 30)
        if market == "ALL":
            kospi = fetch_naver_top_amount("KOSPI", count // 2)
            kosdaq = fetch_naver_top_amount("KOSDAQ", count // 2)
            stocks = kospi + kosdaq
        else:
            stocks = fetch_naver_top_amount(market, count)
        return jsonify({"ok": True, "data": stocks})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# ═══════════════════════════════════════════════════════════════════════
#  [4] V5.2 퀀트 통합 로직 — 서버 사이드 풀 파이프라인
# ═══════════════════════════════════════════════════════════════════════
def calc_noise(o, c, h, l):
    """ 노이즈 지수 = 1 - |Open-Close| / (High-Low) """
    if h <= l:
        return 1.0
    return 1.0 - abs(o - c) / (h - l)


def calc_cpk(o, c, h, l):
    """ 공정능력지수 Cpk 근사 — 추세 안정성 + 방향성 """
    rng = h - l
    if rng == 0:
        return 0.0
    trend_ratio = (c - o) / rng       # 양수=상승 추세
    body_ratio = abs(c - o) / rng     # 몸통 비율 = 추세 선명도
    return max(0.0, trend_ratio * 0.6 + body_ratio * 0.4) * 2


def run_v52_pipeline(params):
    """
    V5.2 5단계 통합 파이프라인 (서버 실행)
    params: { market, kValue, noiseThreshold, targetReturn, stopLoss, count }
    """
    market = params.get("market", "KOSDAQ")
    k_value = float(params.get("kValue", 0.2))
    noise_threshold = float(params.get("noiseThreshold", 0.45))
    target_return = float(params.get("targetReturn", 3)) / 100
    stop_loss = float(params.get("stopLoss", 1.5)) / 100
    count = int(params.get("count", 25))

    # ── 1단계 + 2단계: 데이터 수집 & 주도 테마 필터링 ──
    candidates = fetch_naver_top_amount(market, count)

    analyzed = []
    for cand in candidates:
        try:
            ohlc = fetch_naver_ohlc(cand["code"])
            time.sleep(0.15)
        except Exception:
            continue

        o, h, l, c = ohlc["open"], ohlc["high"], ohlc["low"], ohlc["close"]
        ph, pl = ohlc["prevHigh"], ohlc["prevLow"]
        if not o or not h or not l:
            continue

        # 노이즈 지수 & Cpk
        noise = calc_noise(o, c, h, l)
        cpk = calc_cpk(o, c, h, l)
        score = (1 - noise) * 0.5 + cpk * 0.5

        # ── 3단계: V5.2 매수 타점 산출 (래리 윌리엄스 변동성 돌파) ──
        prev_range = ph - pl
        target = o + prev_range * k_value          # 돌파 기준선
        profit_target = target * (1 + target_return)
        stop_price = target * (1 - stop_loss)

        # ── 4단계: 조건부 진입 판정 ──
        # 실시간 주가(close)가 Target 돌파했는지 확인
        breakout = c >= target
        execution = "조건부 매수 가능" if breakout else "관망 (Target 미돌파)"

        analyzed.append({
            **ohlc,
            "noise": round(noise, 4),
            "cpk": round(cpk, 4),
            "score": round(score, 4),
            "target": round(target),
            "profitTarget": round(profit_target),
            "stopPrice": round(stop_price),
            "breakout": breakout,
            "execution": execution,
        })

    # ── 2단계 압축: 노이즈 임계값 통과 + Cpk 양수 → 점수순 정렬 ──
    filtered = [
        s for s in analyzed
        if s["noise"] <= noise_threshold and s["cpk"] > 0
    ]
    filtered.sort(key=lambda x: x["score"], reverse=True)

    return {
        "all": sorted(analyzed, key=lambda x: x["score"], reverse=True),
        "picks": filtered[:2],
        "timestamp": datetime.now().isoformat(),
        "params": {
            "market": market,
            "kValue": k_value,
            "noiseThreshold": noise_threshold,
            "targetReturn": target_return * 100,
            "stopLoss": stop_loss * 100,
        },
    }


@app.route("/api/v52/analyze", methods=["POST"])
def v52_analyze():
    """V5.2 풀 파이프라인 실행 — 프론트엔드 핵심 엔드포인트"""
    try:
        params = request.get_json() or {}
        result = run_v52_pipeline(params)
        return jsonify({"ok": True, **result})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 400


# ═══════════════════════════════════════════════════════════════════════
#  [5] V5.2 백테스트 엔진 — 과거 실제 일봉에 로직을 날짜별로 재현
# ═══════════════════════════════════════════════════════════════════════
#
#  ※ 시뮬레이션과 백테스트의 차이:
#     - 시뮬레이션: 가정한 승률/손익비로 무작위 추정 (신뢰도 낮음)
#     - 백테스트:   과거 실제 시세에 V5.2 로직을 그대로 적용 (신뢰도 높음)
#
#  ※ 정직한 한계 (결과 해석 시 반드시 인지):
#     1) 일봉 데이터만 사용 → 장중 익절/손절 도달 순서를 정확히 알 수 없음.
#        본 엔진은 '익절 우선' 가정 — 하루 안에 익절가·손절가에 둘 다
#        닿았으면 익절로 처리한다. 이는 낙관적 가정이며, 백테스트 결과가
#        실제보다 좋게 나오는 편향을 만든다.
#     2) 종목 유니버스는 '현재 시점' 거래량 상위로 고정 → 생존 편향 존재.
#        (과거 각 날짜의 실제 거래량 순위 복원은 데이터 제약상 불가)
#     3) 거래세(0.18%)·수수료(0.015%×2)·슬리피지(0.1%)를 매 거래 차감.
#     4) 4단계 '호가창 매수세'는 일봉으로 판정 불가 → Target 돌파 여부만 사용.
#
# ═══════════════════════════════════════════════════════════════════════

# 거래 비용 상수
TAX_RATE        = 0.0018    # 거래세 (매도 시)
FEE_RATE        = 0.00015   # 위탁수수료 (매수+매도 각각)
SLIPPAGE_RATE   = 0.001     # 슬리피지 (체결 미끄러짐, 매수+매도 각각)


def fetch_naver_daily_history(stock_code, pages=20):
    """
    네이버 금융 일별 시세를 여러 페이지 긁어 과거 일봉 리스트 반환.
    pages=20 → 약 200거래일(약 10개월). 4년치는 pages를 크게.
    반환: [{date, open, high, low, close, volume}, ...]  (날짜 오름차순)
    """
    rows = []
    for page in range(1, pages + 1):
        url = (f"https://finance.naver.com/item/sise_day.naver"
               f"?code={stock_code}&page={page}")
        try:
            res = requests.get(url, headers=NAVER_HEADERS, timeout=8)
            res.encoding = "euc-kr"
            soup = BeautifulSoup(res.text, "lxml")
            page_rows = soup.select("table.type2 tr")
            got = 0
            for row in page_rows:
                cols = row.select("td")
                if len(cols) < 7:
                    continue
                date_txt = cols[0].get_text(strip=True)
                if not re.match(r"\d{4}\.\d{2}\.\d{2}", date_txt):
                    continue
                rows.append({
                    "date":   date_txt.replace(".", "-"),
                    "close":  _to_int(cols[1].get_text()),
                    "open":   _to_int(cols[3].get_text()),
                    "high":   _to_int(cols[4].get_text()),
                    "low":    _to_int(cols[5].get_text()),
                    "volume": _to_int(cols[6].get_text()),
                })
                got += 1
            if got == 0:
                break  # 더 이상 데이터 없음
            time.sleep(0.12)
        except Exception:
            break
    # 날짜 오름차순 정렬 + 중복 제거
    seen = set()
    uniq = []
    for r in sorted(rows, key=lambda x: x["date"]):
        if r["date"] in seen or not r["open"]:
            continue
        seen.add(r["date"])
        uniq.append(r)
    return uniq


def backtest_v52(params):
    """
    V5.2 백테스트 — 과거 일봉에 5단계 로직을 날짜별로 재현.

    params: {
      market, count,            # 유니버스 (현재 거래량 상위 N종목)
      kValue, noiseThreshold,   # 2~3단계 파라미터
      targetReturn, stopLoss,   # 5단계 익절/손절
      years,                    # 백테스트 기간 (년)
      seed                      # 시드머니
    }
    """
    market         = params.get("market", "KOSDAQ")
    count          = int(params.get("count", 15))
    k_value        = float(params.get("kValue", 0.2))
    noise_thresh   = float(params.get("noiseThreshold", 0.45))
    target_return  = float(params.get("targetReturn", 3)) / 100
    stop_loss      = float(params.get("stopLoss", 1.5)) / 100
    years          = float(params.get("years", 4))
    seed_money     = float(params.get("seed", 1_000_000))

    # 4년 ≈ 988거래일, 페이지당 10행 → 약 100페이지
    pages = int(years * 250 / 10) + 5

    # ── 유니버스 종목의 과거 일봉 전체 수집 ──
    universe = fetch_naver_top_amount(market, count)
    histories = {}
    for stk in universe:
        hist = fetch_naver_daily_history(stk["code"], pages=pages)
        if len(hist) > 30:
            histories[stk["code"]] = {"name": stk["name"], "bars": hist}
        time.sleep(0.1)

    if not histories:
        raise RuntimeError("과거 일봉 데이터를 가져오지 못했습니다.")

    # ── 공통 거래일 축 만들기 (가장 긴 종목 기준) ──
    all_dates = sorted({d for h in histories.values() for d in
                        [b["date"] for b in h["bars"]]})
    # 종목별 날짜→bar 인덱스 맵
    for code, h in histories.items():
        h["map"] = {b["date"]: i for i, b in enumerate(h["bars"])}

    # ── 날짜별 시뮬레이션 ──
    capital = seed_money
    equity_curve = []          # [{date, capital}]
    trades = []                # 개별 체결 기록
    daily_returns = []         # 일간 수익률 (%)
    monthly = {}               # 'YYYY-MM' → 시작/끝 자본
    win_cnt = loss_cnt = flat_cnt = 0
    exit_reason_cnt = {"익절": 0, "손절": 0, "시간청산": 0}

    for di in range(1, len(all_dates)):
        today = all_dates[di]
        ym = today[:7]
        day_start_capital = capital

        # ── 1~2단계: 그날 거래 가능한 종목 + 노이즈/Cpk로 2종목 선정 ──
        #    (전일 bar로 노이즈/Cpk 계산 → 그날 진입 후보 압축)
        scored = []
        for code, h in histories.items():
            if today not in h["map"]:
                continue
            ti = h["map"][today]
            if ti < 1:
                continue
            prev = h["bars"][ti - 1]
            cur  = h["bars"][ti]
            # 전일 봉으로 추세 품질 평가
            noise = calc_noise(prev["open"], prev["close"],
                               prev["high"], prev["low"])
            cpk   = calc_cpk(prev["open"], prev["close"],
                             prev["high"], prev["low"])
            if noise > noise_thresh or cpk <= 0:
                continue
            score = (1 - noise) * 0.5 + cpk * 0.5
            scored.append({
                "code": code, "name": h["name"],
                "score": score, "prev": prev, "cur": cur,
            })
        scored.sort(key=lambda x: x["score"], reverse=True)
        picks = scored[:2]   # V5.2 — 최종 2종목

        # ── 3~5단계: 선정 2종목에 변동성 돌파 진입 + 청산 ──
        if picks:
            invest_per_stock = capital / len(picks)  # 자본 균등 배분
            day_pnl = 0.0
            for p in picks:
                prev, cur = p["prev"], p["cur"]
                prev_range = prev["high"] - prev["low"]
                target = cur["open"] + prev_range * k_value  # 3단계 Target

                # 4단계: 당일 고가가 Target 이상이어야 '돌파→진입'
                if cur["high"] < target:
                    continue  # 관망 (진입 안 함)

                entry = target  # Target 가격에 매수 체결 가정
                tp = entry * (1 + target_return)   # 익절가
                sl = entry * (1 - stop_loss)       # 손절가

                # 5단계: 익절 / 손절 / 시간청산 판정 (일봉 기반)
                #  - 익절가만 닿음     → 익절
                #  - 손절가만 닿음     → 손절
                #  - 둘 다 닿음        → 익절 우선 (낙관적 가정)
                #  - 둘 다 미도달      → 종가로 시간청산 (Zero Overnight)
                #  ※ '익절 우선'은 장중 도달 순서를 알 수 없는 일봉의 한계상
                #    낙관적 가정이며, 백테스트 결과가 실제보다 좋게 나오는
                #    편향을 만든다. 결과 해석 시 반드시 감안할 것.
                hit_tp = cur["high"] >= tp
                hit_sl = cur["low"]  <= sl
                if hit_tp:
                    # 익절가 도달 시 (손절가 동시 도달 여부와 무관하게) 익절 우선
                    exit_price, reason = tp, "익절"
                elif hit_sl:
                    exit_price, reason = sl, "손절"
                else:
                    exit_price, reason = cur["close"], "시간청산"

                # 거래 비용 차감
                buy_cost  = entry * (FEE_RATE + SLIPPAGE_RATE)
                sell_cost = exit_price * (FEE_RATE + SLIPPAGE_RATE + TAX_RATE)
                gross_ret = (exit_price - entry) / entry
                net_ret   = gross_ret - (buy_cost + sell_cost) / entry

                stock_pnl = invest_per_stock * net_ret
                day_pnl += stock_pnl
                exit_reason_cnt[reason] += 1
                trades.append({
                    "date": today, "code": p["code"], "name": p["name"],
                    "entry": round(entry), "exit": round(exit_price),
                    "reason": reason, "ret": round(net_ret * 100, 2),
                })
                if net_ret > 0:   win_cnt += 1
                elif net_ret < 0: loss_cnt += 1
                else:             flat_cnt += 1

            capital += day_pnl

        # 일간/월간 기록
        day_ret = (capital / day_start_capital - 1) * 100
        daily_returns.append(day_ret)
        equity_curve.append({"date": today, "capital": round(capital)})
        if ym not in monthly:
            monthly[ym] = {"start": day_start_capital, "end": capital}
        else:
            monthly[ym]["end"] = capital

    # ── 통계 집계 ──
    total_trades = win_cnt + loss_cnt + flat_cnt
    win_rate = (win_cnt / total_trades * 100) if total_trades else 0
    total_return = (capital / seed_money - 1) * 100

    # 월별 수익률
    monthly_returns = []
    for ym in sorted(monthly.keys()):
        m = monthly[ym]
        monthly_returns.append({
            "month": ym,
            "return": round((m["end"] / m["start"] - 1) * 100, 2),
            "capital": round(m["end"]),
        })

    # 연도별 수익률
    yearly = {}
    for ym in sorted(monthly.keys()):
        yr = ym[:4]
        m = monthly[ym]
        if yr not in yearly:
            yearly[yr] = {"start": m["start"], "end": m["end"]}
        else:
            yearly[yr]["end"] = m["end"]
    yearly_returns = [{
        "year": yr,
        "return": round((v["end"] / v["start"] - 1) * 100, 2),
        "capital": round(v["end"]),
    } for yr, v in sorted(yearly.items())]

    # MDD (최대 낙폭)
    peak = seed_money
    mdd = 0.0
    for pt in equity_curve:
        peak = max(peak, pt["capital"])
        dd = (pt["capital"] - peak) / peak * 100
        mdd = min(mdd, dd)

    # 샤프 지수 근사 (일간 수익률 기준, 무위험수익률 0 가정)
    if daily_returns:
        avg_d = sum(daily_returns) / len(daily_returns)
        var_d = sum((r - avg_d) ** 2 for r in daily_returns) / len(daily_returns)
        std_d = var_d ** 0.5
        sharpe = (avg_d / std_d * (250 ** 0.5)) if std_d > 0 else 0
    else:
        sharpe = 0

    return {
        "summary": {
            "seedMoney": round(seed_money),
            "finalCapital": round(capital),
            "totalReturn": round(total_return, 2),
            "tradingDays": len(all_dates) - 1,
            "totalTrades": total_trades,
            "winCount": win_cnt,
            "lossCount": loss_cnt,
            "winRate": round(win_rate, 1),
            "mdd": round(mdd, 2),
            "sharpe": round(sharpe, 2),
            "exitReasons": exit_reason_cnt,
            "universeSize": len(histories),
            "dateRange": f"{all_dates[0]} ~ {all_dates[-1]}" if all_dates else "",
        },
        "equityCurve": equity_curve,
        "monthlyReturns": monthly_returns,
        "yearlyReturns": yearly_returns,
        "recentTrades": trades[-50:],   # 최근 50건만 전송
        "timestamp": datetime.now().isoformat(),
    }


@app.route("/api/v52/backtest", methods=["POST"])
def v52_backtest():
    """V5.2 백테스트 실행 — 과거 실제 일봉에 로직 재현"""
    try:
        params = request.get_json() or {}
        result = backtest_v52(params)
        return jsonify({"ok": True, **result})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 400


# ═══════════════════════════════════════════════════════════════════════
#  [6] V5.2 분봉 백테스트 — 키움 ka10080 으로 장중 청산 순서 정밀 재현
# ═══════════════════════════════════════════════════════════════════════
#
#  일봉 백테스트와의 결정적 차이:
#    - 일봉:  익절가·손절가 둘 다 닿은 날 → 순서 불명 → '익절 우선' 가정
#    - 분봉:  분봉을 시간순으로 따라가며 익절가/손절가 중
#             '실제로 먼저 닿은 것'을 청산으로 확정 → 가정 불필요
#
#  남는 한계 (분봉으로도 해결 안 됨):
#    - 생존 편향: 유니버스가 '현재 시점' 거래량 상위로 고정
#    - 분봉 1봉 내부 순서: 1분봉 안에서도 고가·저가 순서는 알 수 없음
#      (그래도 일봉 1개보다 60~390배 정밀)
#    - 키움 조회 제한: 기간이 길수록 호출 폭증 → 최근 수개월 권장
#
# ═══════════════════════════════════════════════════════════════════════

def kiwoom_api_call(token, api_id, endpoint, payload, cont_yn="", next_key=""):
    """키움 REST API 단일 호출 (연속조회 헤더 지원)"""
    url = f"{KIWOOM_BASE}{endpoint}"
    headers = {
        "Content-Type": "application/json;charset=UTF-8",
        "Authorization": f"Bearer {token}",
        "api-id": api_id,
    }
    if cont_yn:
        headers["cont-yn"] = cont_yn
    if next_key:
        headers["next-key"] = next_key
    res = requests.post(url, headers=headers, json=payload, timeout=12)
    res.raise_for_status()
    return res.json(), res.headers


def fetch_kiwoom_minute_bars(token, stock_code, base_date, tic_scope="1",
                             max_pages=6):
    """
    키움 ka10080 주식분봉차트조회 — 특정 기준일 기준 분봉 수집.

    stock_code : 종목코드 (예: '005930')
    base_date  : 기준일자 'YYYYMMDD' (이 날짜 이전 분봉을 최신순으로 반환)
    tic_scope  : 분봉 틱범위 ('1'=1분, '3'=3분, '5'=5분, '10','15','30','45','60')
    max_pages  : 연속조회 최대 페이지 (1페이지≈900봉)

    반환: 해당 base_date 하루치 분봉 리스트 (시간 오름차순)
          [{date,time,open,high,low,close,volume}, ...]
    """
    all_bars = []
    cont_yn, next_key = "", ""
    for _ in range(max_pages):
        payload = {
            "stk_cd": stock_code,
            "tic_scope": tic_scope,
            "upd_stkpc_tp": "1",     # 수정주가 반영
            "base_dt": base_date,    # 기준일자 (최근 추가된 파라미터)
        }
        try:
            data, headers = kiwoom_api_call(
                token, "ka10080", "/api/dostk/chart",
                payload, cont_yn, next_key
            )
        except Exception:
            break

        rows = data.get("stk_min_pole_chart_qry") or data.get("output2") or []
        for r in rows:
            # 키움 분봉 응답: cntr_tm 'YYYYMMDDHHMMSS'
            tm = str(r.get("cntr_tm") or r.get("dt") or "")
            if len(tm) < 12:
                continue
            d, t = tm[:8], tm[8:12]
            o = abs(int(float(r.get("open_pric")  or r.get("open")  or 0)))
            h = abs(int(float(r.get("high_pric")  or r.get("high")  or 0)))
            l = abs(int(float(r.get("low_pric")   or r.get("low")   or 0)))
            c = abs(int(float(r.get("cur_prc")    or r.get("close") or 0)))
            v = abs(int(float(r.get("trde_qty")   or r.get("volume") or 0)))
            if not o or not h or not l:
                continue
            all_bars.append({"date": d, "time": t, "open": o,
                             "high": h, "low": l, "close": c, "volume": v})

        # 연속조회 판단
        cont_yn = headers.get("cont-yn", "")
        next_key = headers.get("next-key", "")
        if cont_yn != "Y" or not next_key:
            break
        time.sleep(0.25)  # 키움 rate limit 준수

    # base_date 당일치만 추출 + 시간 오름차순
    today_bars = [b for b in all_bars if b["date"] == base_date]
    today_bars.sort(key=lambda x: x["time"])
    return today_bars


def simulate_intraday_exit(minute_bars, target, tp, sl):
    """
    분봉을 시간순으로 따라가며 V5.2 4~5단계를 정밀 재현.

    minute_bars : 해당 종목·해당일의 분봉 (시간 오름차순)
    target      : 3단계 매수 타점 (변동성 돌파 기준선)
    tp, sl      : 익절가 / 손절가

    반환: dict 또는 None(진입 안 함)
      { entry, entry_time, exit, exit_time, reason }
      reason ∈ {'익절','손절','시간청산'}

    ※ 진입봉 처리 주의:
      "고가가 Target에 닿아 진입"한 분봉은, 그 봉의 저가가 진입 '이전'에
      발생했을 수 있다. 진입봉 저가로 손절을 판정하면 '사기도 전에 손절'
      되는 오류가 생긴다. 따라서 진입봉에서는 익절만 확인하고(진입 후
      추가 상승으로 tp 도달한 경우만 인정), 손절 판정은 '다음 분봉부터'
      적용한다. 이는 1분봉 내부 순서를 알 수 없는 데서 오는 불가피한
      처리이며, 일봉 백테스트보다는 비교할 수 없이 정밀하다.
    """
    if not minute_bars:
        return None

    entered = False
    entry_price = entry_time = None

    for bar in minute_bars:
        if not entered:
            # 4단계 조건부 진입: 분봉 고가가 Target 도달 → 그 봉에서 매수
            if bar["high"] >= target:
                entered = True
                entry_price = target          # Target 가격에 체결 가정
                entry_time = bar["time"]
                # 진입봉 내부: 손절은 보지 않음(진입 전 저가일 수 있음).
                # 진입 후 추가 상승으로 익절가까지 닿았다면 익절 인정.
                if bar["high"] >= tp:
                    return {"entry": entry_price, "entry_time": entry_time,
                            "exit": tp, "exit_time": bar["time"],
                            "reason": "익절"}
            continue

        # 진입 다음 분봉부터: 순서대로 검사 — 먼저 닿는 쪽이 청산
        hit_tp = bar["high"] >= tp
        hit_sl = bar["low"]  <= sl
        if hit_tp and hit_sl:
            # 같은 분봉에서 둘 다 → 1분봉 내부 순서 불명 → 손절 우선(보수적)
            return {"entry": entry_price, "entry_time": entry_time,
                    "exit": sl, "exit_time": bar["time"], "reason": "손절"}
        if hit_sl:
            return {"entry": entry_price, "entry_time": entry_time,
                    "exit": sl, "exit_time": bar["time"], "reason": "손절"}
        if hit_tp:
            return {"entry": entry_price, "entry_time": entry_time,
                    "exit": tp, "exit_time": bar["time"], "reason": "익절"}

    # 장 종료까지 미도달 → 5단계 시간청산 (마지막 분봉 종가)
    if entered:
        last = minute_bars[-1]
        return {"entry": entry_price, "entry_time": entry_time,
                "exit": last["close"], "exit_time": last["time"],
                "reason": "시간청산"}
    return None  # 하루 종일 Target 미도달 → 관망


def backtest_v52_minute(params):
    """
    V5.2 분봉 백테스트.
      1) 일봉으로 매일의 종목 유니버스 + 노이즈/Cpk 2종목 선정 (기존과 동일)
      2) 선정 2종목에 대해 키움 분봉을 받아 장중 청산 순서를 정밀 재현
      3) 익절/손절 도달 순서를 실제로 확인 → '익절 우선' 가정 제거

    params: {
      appKey, secretKey,         # 키움 인증 (분봉 조회 필수)
      market, count,
      kValue, noiseThreshold, targetReturn, stopLoss,
      months,                    # 백테스트 기간 (개월) — 분봉은 길면 느림
      seed, ticScope             # 분봉 단위 (기본 '1')
    }
    """
    app_key      = params.get("appKey", "").strip()
    secret_key   = params.get("secretKey", "").strip()
    if not app_key or not secret_key:
        raise RuntimeError("분봉 백테스트는 키움 APP Key / Secret Key가 필요합니다.")

    market         = params.get("market", "KOSDAQ")
    count          = int(params.get("count", 10))
    k_value        = float(params.get("kValue", 0.2))
    noise_thresh   = float(params.get("noiseThreshold", 0.45))
    target_return  = float(params.get("targetReturn", 3)) / 100
    stop_loss      = float(params.get("stopLoss", 1.5)) / 100
    months         = float(params.get("months", 3))
    seed_money     = float(params.get("seed", 1_000_000))
    tic_scope      = str(params.get("ticScope", "1"))

    token = get_kiwoom_token(app_key, secret_key)

    # ── 일봉으로 유니버스 + 날짜축 준비 (분봉 호출 최소화 위해) ──
    pages = int(months * 22 / 10) + 4   # 월 22거래일
    universe = fetch_naver_top_amount(market, count)
    histories = {}
    for stk in universe:
        hist = fetch_naver_daily_history(stk["code"], pages=pages)
        if len(hist) > 25:
            histories[stk["code"]] = {"name": stk["name"], "bars": hist}
        time.sleep(0.1)
    if not histories:
        raise RuntimeError("일봉 데이터를 가져오지 못했습니다.")

    for code, h in histories.items():
        h["map"] = {b["date"]: i for i, b in enumerate(h["bars"])}

    all_dates = sorted({d for h in histories.values()
                        for d in [b["date"] for b in h["bars"]]})
    # 백테스트 대상 기간 (최근 months개월)
    cutoff_idx = max(1, len(all_dates) - int(months * 22))
    target_dates = all_dates[cutoff_idx:]

    # ── 날짜별 시뮬레이션 ──
    capital = seed_money
    equity_curve = []
    trades = []
    daily_returns = []
    monthly = {}
    win_cnt = loss_cnt = flat_cnt = 0
    exit_reason_cnt = {"익절": 0, "손절": 0, "시간청산": 0}
    minute_api_calls = 0

    for today in target_dates:
        ym = today[:7]
        day_start_capital = capital

        # 1~2단계: 전일 봉으로 노이즈/Cpk → 2종목 선정
        scored = []
        for code, h in histories.items():
            if today not in h["map"]:
                continue
            ti = h["map"][today]
            if ti < 1:
                continue
            prev = h["bars"][ti - 1]
            cur  = h["bars"][ti]
            noise = calc_noise(prev["open"], prev["close"],
                               prev["high"], prev["low"])
            cpk = calc_cpk(prev["open"], prev["close"],
                           prev["high"], prev["low"])
            if noise > noise_thresh or cpk <= 0:
                continue
            score = (1 - noise) * 0.5 + cpk * 0.5
            scored.append({"code": code, "name": h["name"],
                           "score": score, "prev": prev, "cur": cur})
        scored.sort(key=lambda x: x["score"], reverse=True)
        picks = scored[:2]

        if picks:
            invest_per_stock = capital / len(picks)
            day_pnl = 0.0
            for p in picks:
                prev, cur = p["prev"], p["cur"]
                prev_range = prev["high"] - prev["low"]
                target = cur["open"] + prev_range * k_value   # 3단계
                tp = target * (1 + target_return)
                sl = target * (1 - stop_loss)

                # ── 분봉으로 4~5단계 정밀 재현 ──
                minute_bars = fetch_kiwoom_minute_bars(
                    token, p["code"], today, tic_scope=tic_scope
                )
                minute_api_calls += 1
                time.sleep(0.2)  # rate limit

                result = simulate_intraday_exit(minute_bars, target, tp, sl)
                if result is None:
                    continue  # 관망 (Target 미돌파)

                entry = result["entry"]
                exit_price = result["exit"]
                reason = result["reason"]

                buy_cost  = entry * (FEE_RATE + SLIPPAGE_RATE)
                sell_cost = exit_price * (FEE_RATE + SLIPPAGE_RATE + TAX_RATE)
                gross_ret = (exit_price - entry) / entry
                net_ret   = gross_ret - (buy_cost + sell_cost) / entry

                day_pnl += invest_per_stock * net_ret
                exit_reason_cnt[reason] += 1
                trades.append({
                    "date": today, "code": p["code"], "name": p["name"],
                    "entry": round(entry), "exit": round(exit_price),
                    "entryTime": result["entry_time"],
                    "exitTime": result["exit_time"],
                    "reason": reason, "ret": round(net_ret * 100, 2),
                })
                if net_ret > 0:   win_cnt += 1
                elif net_ret < 0: loss_cnt += 1
                else:             flat_cnt += 1

            capital += day_pnl

        day_ret = (capital / day_start_capital - 1) * 100
        daily_returns.append(day_ret)
        equity_curve.append({"date": today, "capital": round(capital)})
        if ym not in monthly:
            monthly[ym] = {"start": day_start_capital, "end": capital}
        else:
            monthly[ym]["end"] = capital

    # ── 통계 집계 ──
    total_trades = win_cnt + loss_cnt + flat_cnt
    win_rate = (win_cnt / total_trades * 100) if total_trades else 0
    total_return = (capital / seed_money - 1) * 100

    monthly_returns = []
    for ym in sorted(monthly.keys()):
        m = monthly[ym]
        monthly_returns.append({
            "month": ym,
            "return": round((m["end"] / m["start"] - 1) * 100, 2),
            "capital": round(m["end"]),
        })

    yearly = {}
    for ym in sorted(monthly.keys()):
        yr = ym[:4]
        m = monthly[ym]
        if yr not in yearly:
            yearly[yr] = {"start": m["start"], "end": m["end"]}
        else:
            yearly[yr]["end"] = m["end"]
    yearly_returns = [{
        "year": yr,
        "return": round((v["end"] / v["start"] - 1) * 100, 2),
        "capital": round(v["end"]),
    } for yr, v in sorted(yearly.items())]

    peak = seed_money
    mdd = 0.0
    for pt in equity_curve:
        peak = max(peak, pt["capital"])
        dd = (pt["capital"] - peak) / peak * 100
        mdd = min(mdd, dd)

    if daily_returns:
        avg_d = sum(daily_returns) / len(daily_returns)
        var_d = sum((r - avg_d) ** 2 for r in daily_returns) / len(daily_returns)
        std_d = var_d ** 0.5
        sharpe = (avg_d / std_d * (250 ** 0.5)) if std_d > 0 else 0
    else:
        sharpe = 0

    return {
        "mode": "minute",
        "ticScope": tic_scope,
        "summary": {
            "seedMoney": round(seed_money),
            "finalCapital": round(capital),
            "totalReturn": round(total_return, 2),
            "tradingDays": len(target_dates),
            "totalTrades": total_trades,
            "winCount": win_cnt,
            "lossCount": loss_cnt,
            "winRate": round(win_rate, 1),
            "mdd": round(mdd, 2),
            "sharpe": round(sharpe, 2),
            "exitReasons": exit_reason_cnt,
            "universeSize": len(histories),
            "minuteApiCalls": minute_api_calls,
            "dateRange": (f"{target_dates[0]} ~ {target_dates[-1]}"
                          if target_dates else ""),
        },
        "equityCurve": equity_curve,
        "monthlyReturns": monthly_returns,
        "yearlyReturns": yearly_returns,
        "recentTrades": trades[-60:],
        "timestamp": datetime.now().isoformat(),
    }


@app.route("/api/v52/backtest-minute", methods=["POST"])
def v52_backtest_minute():
    """V5.2 분봉 백테스트 — 키움 분봉으로 장중 청산 순서 정밀 재현"""
    try:
        params = request.get_json() or {}
        result = backtest_v52_minute(params)
        return jsonify({"ok": True, **result})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 400


# ═══════════════════════════════════════════════════════════════════════
#  [7] 실전 기록장 — 매일 추천 + 결과 저장, 월별 누적 수익률 집계
# ═══════════════════════════════════════════════════════════════════════
#
#  데이터 구조 (journal.json):
#    {
#      "seedMoney": 1000000,
#      "entries": {
#        "2026-05-15": {
#          "picks": [
#            { code, name, currentPrice, buyTarget, profitTarget, stopPrice,
#              noise, cpk, score, prevHigh, prevLow,
#              indicatorReason,           # 자동 생성된 지표 사유
#              issueReason,               # 사용자 직접 입력 (선택)
#              result: {
#                executed: bool,          # 진입 성공 여부 (Target 돌파)
#                exitPrice: int,          # 청산가 (실제 거래 결과)
#                reason: '익절'|'손절'|'시간청산'|'관망',
#                netReturn: float,        # 거래비용 차감 순수익률 (%)
#              } | null                  # null = 아직 결과 입력 안 함
#            }, ...
#          ]
#        }, ...
#      }
#    }
#
#  ※ 시드 50:50 분할 규정에 따라, 그 날의 자본 절반씩을 두 종목에 투입.
#     하루 손익률 = (종목1 net + 종목2 net) / 2  (둘 다 거래된 경우)
#
# ═══════════════════════════════════════════════════════════════════════

def _load_journal():
    """기록장 JSON 로드 — 없으면 빈 구조 반환"""
    if not os.path.exists(JOURNAL_PATH):
        return {"seedMoney": 1_000_000, "entries": {}}
    try:
        with open(JOURNAL_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "entries" not in data:
            data["entries"] = {}
        if "seedMoney" not in data:
            data["seedMoney"] = 1_000_000
        return data
    except Exception:
        return {"seedMoney": 1_000_000, "entries": {}}


def _save_journal(data):
    """기록장 JSON 저장 (원자적 쓰기)"""
    tmp = JOURNAL_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, JOURNAL_PATH)


def _generate_indicator_reason(pick):
    """
    자동 지표 사유 문구 생성 (이슈는 별도 입력)
    가격 데이터 기반으로만 작성 — 가짜 이슈 지어내지 않음
    """
    noise = pick.get("noise", 0)
    cpk = pick.get("cpk", 0)
    score = pick.get("score", 0)

    # 노이즈 수준 평가
    if noise < 0.25:
        noise_desc = f"노이즈 지수가 {noise:.2f}로 추세 순도가 매우 높음"
    elif noise < 0.40:
        noise_desc = f"노이즈 지수가 {noise:.2f}로 추세가 비교적 깨끗함"
    else:
        noise_desc = f"노이즈 지수가 {noise:.2f}로 추세 선명도가 보통 수준"

    # Cpk 수준 평가
    if cpk > 1.0:
        cpk_desc = f"Cpk가 {cpk:.2f}로 상승 추세의 안정성이 견고함"
    elif cpk > 0.5:
        cpk_desc = f"Cpk가 {cpk:.2f}로 상승 추세가 형성됨"
    else:
        cpk_desc = f"Cpk가 {cpk:.2f}로 상승 동력이 다소 약함"

    return f"{noise_desc}. {cpk_desc}. 종합 점수 {score*100:.1f}점으로 후보군 상위에 위치."


def _calc_monthly_summary(journal):
    """
    월별 누적 수익률 집계.
    하루 손익률 = (종목1 net + 종목2 net) / 2  (관망/미입력은 0%로 처리)
    월 누적 = (1+r1)*(1+r2)*...*(1+rN) - 1   (복리)
    """
    seed = journal.get("seedMoney", 1_000_000)
    entries = journal.get("entries", {})

    # 날짜 오름차순으로 일간 손익률 계산
    daily = []
    for date in sorted(entries.keys()):
        day = entries[date]
        picks = day.get("picks", [])
        if not picks:
            continue
        rets = []
        for p in picks:
            r = p.get("result") or {}
            net = r.get("netReturn")
            if net is None:
                # 아직 입력 안 한 종목 → 0% (보수적: 거래 안 한 셈)
                rets.append(0.0)
            else:
                rets.append(float(net))
        # 50:50 분할 → 평균
        daily_ret = sum(rets) / len(rets) if rets else 0.0
        daily.append({"date": date, "ret": daily_ret})

    # 월별 그룹화 + 복리 누적
    monthly = {}
    for d in daily:
        ym = d["date"][:7]
        if ym not in monthly:
            monthly[ym] = {"month": ym, "tradeDays": 0, "ret": 0.0,
                           "compoundFactor": 1.0, "wins": 0, "losses": 0,
                           "flats": 0}
        m = monthly[ym]
        m["tradeDays"] += 1
        m["compoundFactor"] *= (1 + d["ret"] / 100)
        # 일별 승패 카운트
        if   d["ret"] > 0: m["wins"]   += 1
        elif d["ret"] < 0: m["losses"] += 1
        else:              m["flats"]  += 1

    # 누적 자산 추이 + 월 수익률 계산
    capital = float(seed)
    monthly_list = []
    capital_curve = []   # [{date, capital}]
    running_factor = 1.0
    last_factor = {}     # ym → 누적 팩터 (전월말)

    # 자산 곡선 (일별)
    for d in daily:
        capital *= (1 + d["ret"] / 100)
        capital_curve.append({"date": d["date"], "capital": round(capital)})

    # 월별 통계 정리
    sorted_months = sorted(monthly.keys())
    prev_capital = float(seed)
    for ym in sorted_months:
        m = monthly[ym]
        month_return_pct = (m["compoundFactor"] - 1) * 100
        # 그 달 시작 자본 → 끝 자본
        end_capital = prev_capital * m["compoundFactor"]
        monthly_list.append({
            "month": ym,
            "tradeDays": m["tradeDays"],
            "wins": m["wins"],
            "losses": m["losses"],
            "flats": m["flats"],
            "return": round(month_return_pct, 2),
            "startCapital": round(prev_capital),
            "endCapital": round(end_capital),
            "profitAmount": round(end_capital - prev_capital),
        })
        prev_capital = end_capital

    final_capital = prev_capital
    total_return = (final_capital / seed - 1) * 100 if seed > 0 else 0
    total_profit = final_capital - seed

    # 전체 통계
    total_trade_days = sum(m["tradeDays"] for m in monthly_list)
    total_wins = sum(m["wins"] for m in monthly_list)
    total_losses = sum(m["losses"] for m in monthly_list)

    return {
        "seedMoney": round(seed),
        "finalCapital": round(final_capital),
        "totalReturn": round(total_return, 2),
        "totalProfit": round(total_profit),
        "totalTradeDays": total_trade_days,
        "winDays": total_wins,
        "lossDays": total_losses,
        "monthly": monthly_list,
        "capitalCurve": capital_curve,
    }


# ── API 엔드포인트 ──

@app.route("/api/journal/seed", methods=["POST"])
def journal_set_seed():
    """시드머니 설정"""
    try:
        body = request.get_json() or {}
        seed = float(body.get("seedMoney", 0))
        if seed < 10000:
            raise ValueError("시드머니는 1만원 이상이어야 합니다.")
        with _journal_lock:
            j = _load_journal()
            j["seedMoney"] = seed
            _save_journal(j)
        return jsonify({"ok": True, "seedMoney": seed})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/journal/save-recommendation", methods=["POST"])
def journal_save_recommendation():
    """
    오늘의 추천 종목 저장 (현재 분석 결과를 기록장에 영구 저장)
    body: { date, picks: [...] }
    """
    try:
        body = request.get_json() or {}
        date = body.get("date") or datetime.now().strftime("%Y-%m-%d")
        picks = body.get("picks", [])
        if not picks:
            raise ValueError("저장할 추천 종목이 없습니다.")

        with _journal_lock:
            j = _load_journal()
            # 각 pick에 자동 지표 사유 추가 + result 초기화
            saved_picks = []
            for p in picks:
                saved_picks.append({
                    "code": p.get("code"),
                    "name": p.get("name"),
                    "currentPrice": p.get("close") or p.get("currentPrice", 0),
                    "buyTarget": p.get("target") or p.get("buyTarget", 0),
                    "profitTarget": p.get("profitTarget", 0),
                    "stopPrice": p.get("stopPrice", 0),
                    "noise": p.get("noise", 0),
                    "cpk": p.get("cpk", 0),
                    "score": p.get("score", 0),
                    "prevHigh": p.get("prevHigh", 0),
                    "prevLow": p.get("prevLow", 0),
                    "open": p.get("open", 0),
                    "indicatorReason": _generate_indicator_reason(p),
                    "issueReason": p.get("issueReason", ""),
                    "result": None,
                })
            j["entries"][date] = {"picks": saved_picks}
            _save_journal(j)
        return jsonify({"ok": True, "date": date, "count": len(saved_picks)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/journal/save-result", methods=["POST"])
def journal_save_result():
    """
    특정 날짜·종목의 거래 결과 입력
    body: { date, code, executed, exitPrice, reason, issueReason? }
    """
    try:
        body = request.get_json() or {}
        date = body["date"]
        code = body["code"]
        executed = bool(body.get("executed", False))
        exit_price = float(body.get("exitPrice", 0)) if executed else 0
        reason = body.get("reason", "관망")

        with _journal_lock:
            j = _load_journal()
            day = j["entries"].get(date)
            if not day:
                raise ValueError(f"{date} 추천 기록이 없습니다.")
            target_pick = None
            for p in day["picks"]:
                if p["code"] == code:
                    target_pick = p
                    break
            if not target_pick:
                raise ValueError(f"{date}의 {code} 종목이 없습니다.")

            if not executed:
                # 관망 — 수익률 0%
                target_pick["result"] = {
                    "executed": False, "exitPrice": 0,
                    "reason": "관망", "netReturn": 0.0,
                }
            else:
                # 거래 비용 차감 순수익률 계산
                entry = float(target_pick["buyTarget"])
                if entry <= 0:
                    raise ValueError("매수 타점이 0입니다.")
                buy_cost  = entry * (FEE_RATE + SLIPPAGE_RATE)
                sell_cost = exit_price * (FEE_RATE + SLIPPAGE_RATE + TAX_RATE)
                gross = (exit_price - entry) / entry
                net = gross - (buy_cost + sell_cost) / entry
                target_pick["result"] = {
                    "executed": True,
                    "exitPrice": round(exit_price),
                    "reason": reason,
                    "netReturn": round(net * 100, 2),
                }

            # 사용자가 이슈 사유도 함께 입력했다면 갱신
            if "issueReason" in body:
                target_pick["issueReason"] = body["issueReason"]

            _save_journal(j)
        return jsonify({"ok": True, "result": target_pick["result"]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/journal/update-issue", methods=["POST"])
def journal_update_issue():
    """이슈 사유만 별도 입력/수정"""
    try:
        body = request.get_json() or {}
        date = body["date"]
        code = body["code"]
        issue = body.get("issueReason", "")

        with _journal_lock:
            j = _load_journal()
            day = j["entries"].get(date)
            if not day:
                raise ValueError(f"{date} 기록이 없습니다.")
            for p in day["picks"]:
                if p["code"] == code:
                    p["issueReason"] = issue
                    _save_journal(j)
                    return jsonify({"ok": True})
            raise ValueError(f"{date}의 {code} 종목이 없습니다.")
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/journal/summary", methods=["GET"])
def journal_summary():
    """월별 누적 수익률 + 전체 통계 조회"""
    try:
        with _journal_lock:
            j = _load_journal()
        summary = _calc_monthly_summary(j)
        return jsonify({"ok": True, **summary})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/journal/entries", methods=["GET"])
def journal_entries():
    """전체 기록장 조회 (날짜별 추천 + 결과)"""
    try:
        with _journal_lock:
            j = _load_journal()
        # 날짜 내림차순 정렬
        sorted_entries = []
        for date in sorted(j.get("entries", {}).keys(), reverse=True):
            sorted_entries.append({"date": date, **j["entries"][date]})
        return jsonify({
            "ok": True,
            "seedMoney": j.get("seedMoney", 1_000_000),
            "entries": sorted_entries,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/journal/delete", methods=["POST"])
def journal_delete():
    """특정 날짜 기록 삭제"""
    try:
        body = request.get_json() or {}
        date = body["date"]
        with _journal_lock:
            j = _load_journal()
            if date in j.get("entries", {}):
                del j["entries"][date]
                _save_journal(j)
                return jsonify({"ok": True})
            return jsonify({"ok": False, "error": "해당 날짜 기록이 없습니다."}), 404
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# ───────────────────────────────────────────────────────────────────────
#  백업 / 복원 — Render 무료 플랜 디스크 휘발성 대비
# ───────────────────────────────────────────────────────────────────────
#  사용 흐름:
#    [백업]  GET  /api/journal/backup
#            → journal.json 파일을 그대로 다운로드 (폰에 저장)
#    [복원]  POST /api/journal/restore
#            → 백업 파일을 업로드해 journal.json 통째로 교체
#    Render 서비스가 재배포되어 데이터가 사라져도, 폰에 저장해둔 백업
#    파일을 복원하면 그대로 되돌릴 수 있다.
# ───────────────────────────────────────────────────────────────────────

@app.route("/api/journal/backup", methods=["GET"])
def journal_backup():
    """기록장 전체를 JSON 파일로 다운로드"""
    try:
        with _journal_lock:
            j = _load_journal()
        # 다운로드 파일명에 날짜 포함
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"quant_journal_backup_{date_str}.json"
        body = json.dumps(j, ensure_ascii=False, indent=2)
        resp = make_response(body)
        resp.headers["Content-Type"] = "application/json; charset=utf-8"
        resp.headers["Content-Disposition"] = (
            f'attachment; filename="{filename}"'
        )
        return resp
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/journal/restore", methods=["POST"])
def journal_restore():
    """
    백업 파일로 기록장 복원.
    body: { data: {...} }  또는  multipart 파일 업로드
    mode: 'replace' (전체 교체) | 'merge' (병합 — 기존+백업, 같은 날짜는 백업 우선)
    """
    try:
        body = request.get_json(silent=True) or {}
        backup_data = body.get("data")
        mode = body.get("mode", "merge")  # 기본은 안전한 병합

        if not backup_data or not isinstance(backup_data, dict):
            return jsonify({"ok": False, "error": "유효한 백업 데이터가 없습니다."}), 400
        if "entries" not in backup_data:
            return jsonify({"ok": False, "error": "백업 파일 형식이 올바르지 않습니다 (entries 누락)."}), 400

        backup_entries = backup_data.get("entries", {})
        backup_seed = backup_data.get("seedMoney")

        with _journal_lock:
            current = _load_journal()
            if mode == "replace":
                # 전체 교체
                current["entries"] = backup_entries
                if backup_seed is not None:
                    current["seedMoney"] = backup_seed
                restored_count = len(backup_entries)
                added_count = restored_count
            else:
                # 병합 (같은 날짜는 백업 우선, 기존 날짜는 유지)
                if "entries" not in current:
                    current["entries"] = {}
                added_count = 0
                overwritten_count = 0
                for date, entry in backup_entries.items():
                    if date in current["entries"]:
                        overwritten_count += 1
                    else:
                        added_count += 1
                    current["entries"][date] = entry
                restored_count = added_count + overwritten_count
                # 시드는 현재 값이 기본 100만원이면 백업값으로 갱신
                if backup_seed is not None and current.get("seedMoney", 1_000_000) == 1_000_000:
                    current["seedMoney"] = backup_seed
            _save_journal(current)

        return jsonify({
            "ok": True,
            "mode": mode,
            "restoredCount": restored_count,
            "addedCount": added_count,
            "totalEntries": len(current["entries"]),
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/journal/clear", methods=["POST"])
def journal_clear():
    """기록장 전체 초기화 (확인 후 사용 — 위험)"""
    try:
        body = request.get_json() or {}
        if body.get("confirm") != "DELETE-ALL":
            return jsonify({"ok": False, "error": "확인 문구가 일치하지 않습니다."}), 400
        with _journal_lock:
            _save_journal({"seedMoney": 1_000_000, "entries": {}})
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# ───────────────────────────────────────────────────────────────────────
#  자동 성과 확인 — 장 마감 후 일봉으로 자동 결과 산출
# ───────────────────────────────────────────────────────────────────────
#  사용 흐름:
#    1) 사용자가 추천 카드에서 "오늘 추천 기록장에 저장" 클릭
#    2) 장 마감 후 (오후 4시 이후) 기록장에서 "결과 자동 채우기" 클릭
#    3) 서버가 그날 일봉을 받아 종목별로 익절/손절/시간청산/관망 자동 판정
#
#  판정 로직 (백테스트와 동일한 규칙):
#    - 당일 고가 < Target           → 관망 (Target 미돌파)
#    - 당일 고가 >= 익절가          → 익절 (청산가 = 익절가)
#    - 당일 저가 <= 손절가          → 손절 (청산가 = 손절가)
#    - 둘 다 닿음                   → 익절 우선 (낙관, 일봉 한계)
#    - 둘 다 미도달, Target 돌파    → 시간청산 (청산가 = 종가)
#
#  ※ 일봉 한계: "익절가·손절가 둘 다 닿은 날"의 실제 순서는 알 수 없어
#     낙관적으로 익절을 우선합니다. 실제 거래 결과와 다를 수 있음.
#     정확하려면 분봉이 필요 (백테스트의 분봉 모드 참조).
# ───────────────────────────────────────────────────────────────────────

def _judge_result(ohlc, pick):
    """일봉 OHLC와 추천 정보로 결과 판정"""
    target = float(pick.get("buyTarget", 0))
    tp     = float(pick.get("profitTarget", 0))
    sl     = float(pick.get("stopPrice", 0))

    high  = ohlc.get("high", 0)
    low   = ohlc.get("low", 0)
    close = ohlc.get("close", 0)

    if not target or not high or not low:
        return {"executed": False, "exitPrice": 0,
                "reason": "데이터 없음", "netReturn": 0.0,
                "ohlc": ohlc}

    # 4단계: Target 돌파 여부
    if high < target:
        return {"executed": False, "exitPrice": 0,
                "reason": "관망", "netReturn": 0.0, "ohlc": ohlc}

    # 5단계: 익절/손절/시간청산
    hit_tp = high >= tp
    hit_sl = low  <= sl
    if hit_tp:               # 익절 우선 (둘 다 닿음 포함)
        exit_price, reason = tp, "익절"
    elif hit_sl:
        exit_price, reason = sl, "손절"
    else:
        exit_price, reason = close, "시간청산"

    # 거래 비용 차감 순수익률
    entry = target
    buy_cost  = entry * (FEE_RATE + SLIPPAGE_RATE)
    sell_cost = exit_price * (FEE_RATE + SLIPPAGE_RATE + TAX_RATE)
    gross = (exit_price - entry) / entry
    net = gross - (buy_cost + sell_cost) / entry

    return {
        "executed": True,
        "exitPrice": round(exit_price),
        "reason": reason,
        "netReturn": round(net * 100, 2),
        "ohlc": ohlc,
    }


@app.route("/api/journal/auto-fill-results", methods=["POST"])
def journal_auto_fill_results():
    """
    특정 날짜의 추천 종목들에 대해 결과를 자동으로 채움.
    body: { date, overwrite?:bool }   date 미지정 시 가장 최근 미입력 날짜

    반환: 각 종목별 판정 결과 + 그날 50:50 평균 수익률
    """
    try:
        body = request.get_json() or {}
        target_date = body.get("date")
        overwrite = bool(body.get("overwrite", False))

        with _journal_lock:
            j = _load_journal()

        if target_date:
            if target_date not in j["entries"]:
                return jsonify({"ok": False,
                    "error": f"{target_date} 추천 기록이 없습니다."}), 404
            dates = [target_date]
        else:
            # 결과 미입력 종목이 있는 모든 날짜
            dates = []
            for d in sorted(j["entries"].keys()):
                picks = j["entries"][d].get("picks", [])
                if any(p.get("result") is None for p in picks):
                    dates.append(d)
            if not dates:
                return jsonify({"ok": True, "message": "이미 모든 결과가 입력되어 있습니다.",
                                "filled": []})

        # 오늘 날짜인 경우 장 마감 시간 체크 (한국 시간 기준)
        # 서버 시간이 UTC일 수 있어 +9 보정
        from datetime import timezone
        kst = timezone(timedelta(hours=9))
        kst_now = datetime.now(kst)
        today_kst = kst_now.strftime("%Y-%m-%d")
        market_closed = kst_now.hour >= 16  # 16:00 KST 이후

        results = []
        for d in dates:
            picks = j["entries"][d].get("picks", [])

            # 오늘 날짜인데 아직 장 마감 전이면 경고
            if d == today_kst and not market_closed:
                results.append({
                    "date": d,
                    "warning": "오늘 장 마감 전입니다. 정확한 결과는 16:00 이후 확인 가능합니다.",
                    "picks": [],
                })
                continue

            day_results = []
            for p in picks:
                # 이미 결과 있고 overwrite=False면 건너뜀
                if p.get("result") is not None and not overwrite:
                    day_results.append({
                        "code": p["code"], "name": p["name"],
                        "skipped": True, "reason": "이미 입력됨",
                        "result": p["result"],
                    })
                    continue

                # 네이버에서 해당일 OHLC 조회
                try:
                    # 일별 시세에서 해당 날짜 찾기
                    history = fetch_naver_daily_history(p["code"], pages=3)
                    target_ohlc = None
                    for bar in history:
                        if bar["date"] == d:
                            target_ohlc = bar
                            break
                    if not target_ohlc:
                        day_results.append({
                            "code": p["code"], "name": p["name"],
                            "skipped": True,
                            "reason": f"{d} 일봉 데이터를 찾을 수 없음 (휴장일?)",
                        })
                        continue

                    result = _judge_result(target_ohlc, p)
                    day_results.append({
                        "code": p["code"], "name": p["name"],
                        "skipped": False, **result,
                    })
                except Exception as e:
                    day_results.append({
                        "code": p["code"], "name": p["name"],
                        "skipped": True, "reason": f"조회 오류: {e}",
                    })

                time.sleep(0.15)  # 네이버 부하 방지

            # 그날 50:50 평균 수익률 계산
            valid_returns = [r["netReturn"] for r in day_results
                             if "netReturn" in r and not r.get("skipped")]
            day_avg = (sum(valid_returns) / len(picks)) if picks else 0.0

            results.append({
                "date": d, "picks": day_results,
                "dailyReturn": round(day_avg, 2),
            })

            # 결과를 journal에 저장
            with _journal_lock:
                j = _load_journal()
                for r in day_results:
                    if r.get("skipped"): continue
                    for p in j["entries"][d]["picks"]:
                        if p["code"] == r["code"]:
                            p["result"] = {
                                "executed": r["executed"],
                                "exitPrice": r["exitPrice"],
                                "reason": r["reason"],
                                "netReturn": r["netReturn"],
                                "autoFilled": True,
                            }
                            break
                _save_journal(j)

        return jsonify({"ok": True, "filled": results,
                        "totalDates": len(results)})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/journal/auto-fill-today", methods=["POST"])
def journal_auto_fill_today():
    """오늘 추천에 대해서만 자동 채움 (편의 엔드포인트)"""
    from datetime import timezone
    kst = timezone(timedelta(hours=9))
    today = datetime.now(kst).strftime("%Y-%m-%d")
    # 내부적으로 auto-fill-results 와 같은 로직 호출
    with app.test_request_context(json={"date": today}):
        return journal_auto_fill_results()


# ═══════════════════════════════════════════════════════════════════════
#  정적 파일 서빙 (대시보드 HTML)
# ═══════════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return send_from_directory(".", "dashboard.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(".", path)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.now().isoformat()})


# ═══════════════════════════════════════════════════════════════════════
#  실행
#  - 로컬:  python proxy_server.py  → http://localhost:8000
#  - Render: gunicorn proxy_server:app  (PORT 환경변수 자동 사용)
# ═══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print("=" * 65)
    print("  매일 투자 추천 V5.2 — 프록시 서버 시작")
    print("=" * 65)
    print(f"  대시보드:   http://localhost:{port}")
    print(f"  헬스체크:   http://localhost:{port}/health")
    if ENABLE_PIN_AUTH:
        # _load_config() 호출되며 최초 PIN 자동 생성·출력
        _load_config()
    else:
        print("  🔓 PIN 인증 OFF (환경변수 ENABLE_PIN_AUTH=1 로 활성화 가능)")
    print("-" * 65)
    print("  ※ dashboard.html 파일을 이 스크립트와 같은 폴더에 두세요.")
    print("=" * 65)
    app.run(host="0.0.0.0", port=port, debug=False)
