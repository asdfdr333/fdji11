#!/usr/bin/env bash
###############################################################################
# amap_direct_regeo.sh —— 逆地理编码压测（走后端 POST /api/map/lngLatToAddress）
#
# 为什么是这个接口:
#   /api/map/lngLatToAddress 在 Map 控制器里 $noNeedLogin/$noNeedRight/$noNeedEncrypt 全部
#   为 ['*']，自带限流 checkRateLimit() 首行 return true 未启用 —— 即它免登录、免鉴权、
#   免签名。因此压测不再需要先调 /api/user/login，从而绕开正式环境登录接口那条
#   「疑是暴力请求」边缘防护规则（该规则只打 login，与本接口无关）。
#   它调的是高德 v3/geocode/regeo，key 取自数据库 fa_map 的 web_service 列表
#   （MapModel::getWebKeyList()，带轮换与配额耗尽标记），与 /api/common/getRegeo
#   （用 .env 的 [map] key）是两套不同的 key，压测结果不可直接互相类比。
#   另注: 因 $noNeedEncrypt=['*']，即使 platform=ios 也不会真正走 RSA 验签（脚本仍会
#   照常签名，方便你切到 getRegeo 等需验签的接口做对比）。
#
# 历史背景: 最早「直连 restapi.amap.com」的模式已失效 —— getMap 下发的 web_service key
#   在高德侧开了 IP 白名单，非白名单出口 IP 会 100% 返回 infocode=10005
#   INVALID_USER_IP；改为请求后端后，高德调用发生在服务器侧（白名单内）。
#
# 流程:
#   1) 默认匿名直连（NEED_LOGIN=0），不取 token。若需压需要登录态的接口（如
#      /api/common/getRegeo）再置 NEED_LOGIN=1 走登录；登录被 login 防护拦截时会
#      退避重试并给出诊断（TOKEN=xxx 可直接跳过登录）
#   2) 门禁探测：先单发 1 次，非成功结构立即终止并给出诊断，不把线程和配额
#      浪费在必然失败的请求上（GATE=0 可跳过）
#   3) 限速 + 限并发持续 DURATION 秒，每个请求经纬度随机（必须带 >=3 位小数，
#      否则被 validateLatLng 拒为「经纬度格式不正确」）
#   4) 统计成功率、延迟分位、后端 code 分布、msg（含高德错误码）分布
#
# 用法:
#   ./tests/amap_direct_regeo.sh                              # 匿名直连 lngLatToAddress
#   CONCURRENCY=8 RATE=5 DURATION=600 ./tests/amap_direct_regeo.sh
#   RATE=6 DURATION=6 ./tests/amap_direct_regeo.sh            # 先跑6秒快速验证
#   PLATFORM=ios ./tests/amap_direct_regeo.sh                 # 还原 App 真实签名链路
#   BASE_URL=https://api.shanfly.com ./tests/amap_direct_regeo.sh   # 改打测试环境
#   REGO_PATH=/api/common/getRegeo PARAM_LNG=longitude PARAM_LAT=latitude REQ_METHOD=GET NEED_LOGIN=1 \
#     ./tests/amap_direct_regeo.sh                            # A/B 对比旧接口（参数名+方式都不同）
#   TOKEN=xxxxxxxx-xxxx-... NEED_LOGIN=1 ./tests/amap_direct_regeo.sh  # 复用 token 但不重登
#
# 判读（HTTP 200 不代表成功，以 JSON 内 code / msg 为准）:
#   code=1 且 data.formatted_address 为非空字符串 => 高德真实解析出地址，延迟数据可信
#     注：境外/海面点高德仍返 status=1，本接口会回 code=1 但 formatted_address 为 []
#     → 属「成功但空结果」，不计入已解析；日志里会标「空结果(海面/境外)」
#   msg=INVALID_USER_IP      => fa_map 的 web_service key 白名单不含服务器出口 IP
#   msg=INVALID_USER_KEY / USERKEY_PLAT_NOMATCH => key 失效或平台类型不符
#   msg=CUQPS_HAS_EXCEEDED_THE_LIMIT / 10021 / 10014 => 高德并发或配额超限
#   msg=高德API本月已用完      => fa_map 里所有 key 都被标不可用（配额耗尽）
#   msg=高德API调用失败，请稍后刷新重试 => 逐个 key 轮换后仍无一成功
#   msg=经纬度格式不正确      => 坐标小数位不足 3 位或非数值（validateLatLng 硬校验）
#   msg=地址解析失败，请稍后重试 => 高德返回结构里无 formatted_address 键
#   msg=请求过于频繁          => checkRateLimit 被启用后命中（目前代码里未启用）
#   {"code":1,"msg":"发送成功!"} 假成功 => 本机出口 IP 被服务端 IpFirewall 封禁 24h
#   msg=疑是暴力请求         => 仅登录接口会被拦（本接口匿名访问不涉及）
###############################################################################
set -uo pipefail

# ===================== 可配置参数 =====================
BASE_URL="${BASE_URL:-https://sdfgdfss.shanfly.com}"     # 正式环境; api.shanfly.com=测试
ACCOUNT="${ACCOUNT:-13594019185}"                       # 登录手机号（须与 USERTYPE 匹配；13594019185 已被正式环境登录防护拉黑）
PASSWORD="${PASSWORD:-123456}"
TOKEN="${TOKEN:-}"                                       # 已有 token 则跳过登录（避开登录接口的边缘防暴力规则）
LOGIN_RETRY="${LOGIN_RETRY:-5}"                        # 登录被拦时的重试次数
LOGIN_BACKOFF="${LOGIN_BACKOFF:-15}"                   # 重试退避基数（秒，逐次递增）
JPUSH="${JPUSH_REG_ID:-}"                                # 极光 registrationId（无则留空）
USERTYPE="${USERTYPE:-1}"                                # 1=用户端 2=飞手端
PLATFORM="${PLATFORM:-web}"                              # web=明文(默认, 并发上限最高) | ios=逐请求签名(还原App链路)
PRIVATE_KEY="${PRIVATE_KEY:-$(cd "$(dirname "$0")/.." && pwd)/storage/verify/private.pem}"
LOGIN_PATH="${LOGIN_PATH:-/api/user/login}"
REGO_PATH="${REGO_PATH:-/api/map/lngLatToAddress}"        # 后端逆地理编码入口（免登录）
# 参数名随目标接口而变：lngLatToAddress 读 lng/lat；getRegeo 读 longitude/latitude
PARAM_LNG="${PARAM_LNG:-lng}"
PARAM_LAT="${PARAM_LAT:-lat}"
# 请求方式：lngLatToAddress 声明 POST（用 request()->param() 两可）；
# getRegeo 用 request()->get()，必须 GET，否则「参数错误」
REQ_METHOD="${REQ_METHOD:-POST}"
NEED_LOGIN="${NEED_LOGIN:-0}"                            # 0=匿名直连(本接口免登录); 1=先登录取 token（打到 getRegeo 这类需登录接口时置1）

CONCURRENCY="${CONCURRENCY:-10}"                         # 常驻并发上限
RATE="${RATE:-10}"                                       # 全局限速 req/s（注意会真实消耗高德配额）
DURATION="${DURATION:-1200}"                               # 持续时长(秒)
TIMEOUT="${TIMEOUT:-5}"                                  # 单请求超时秒
LON_MIN="${LON_MIN:-73}"; LON_MAX="${LON_MAX:-135}"      # 经度范围(中国大陆)
LAT_MIN="${LAT_MIN:-18}"; LAT_MAX="${LAT_MAX:-53}"       # 纬度范围
GATE="${GATE:-1}"                                        # 1=开跑前门禁探测; 0=跳过
# 门禁用固定国内城市坐标（不用随机点，避免抽到海面/境外导致误判为链路失败）
GATE_LNG="${GATE_LNG:-106.504962}"
GATE_LAT="${GATE_LAT:-29.533155}"
KEEP_RESULTS="${KEEP_RESULTS:-0}"

# ===================== 工具函数 =====================
say()  { printf '\033[1;36m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
now_s() { date +%s; }
gen_nonce() { openssl rand -hex 16; }                    # 32位hex, 等价 iOS uuid 去横线
now() { if command -v perl >/dev/null 2>&1; then perl -MTime::HiRes=time -e 'printf "%.6f", time'; else date +%s; fi; }

# 按 PHP http_build_query(ksort) 语义拼 query（参数值均为安全字符, 无需百分号编码）
build_query() {
  [ "$#" -eq 0 ] && { printf ''; return; }
  printf '%s\n' "$@" | sort -t= -k1,1 | paste -sd'&' -
}

# 随机经纬度查询串（openssl CSPRNG 保证并发不重复; 顺序即签名串顺序）
# 参数名用 PARAM_LNG/PARAM_LAT，%.6f 满足 validateLatLng 的「至少 3 位小数」硬校验
# 结果写入全局 LAST_Q/LAST_LAT/LAST_LON（不要用 $(...) 调用，否则赋值留在子 shell）
gen_regeo_query() {
  local r hi lo lon lat
  r="$(openssl rand -hex 8)"
  hi=$((16#${r:0:8})); lo=$((16#${r:8:8}))
  lon="$(awk -v h="$hi" -v a="$LON_MIN" -v b="$LON_MAX" 'BEGIN{printf "%.6f", a+(b-a)*(h/4294967295)}')"
  lat="$(awk -v h="$lo" -v a="$LAT_MIN" -v b="$LAT_MAX" 'BEGIN{printf "%.6f", a+(b-a)*(h/4294967295)}')"
  LAST_LAT="$lat"; LAST_LON="$lon"
  LAST_Q="$(build_query "$PARAM_LAT=$lat" "$PARAM_LNG=$lon")"
}

# 生成签名 -> "timestamp<TAB>nonce<TAB>sign"
make_sign() {
  local query="$1" ts nonce sign
  ts="$(now_s)"; nonce="$(gen_nonce)"
  # 直接管道给 openssl, 保留签名原文末尾换行（不能经 $(...) 变量中转, 否则丢末尾 \n）
  sign="$(printf '%s\n%s\n%s\n' "$ts" "$nonce" "$query" | openssl dgst -sha256 -sign "$PRIVATE_KEY" | openssl base64 -A)"
  printf '%s\t%s\t%s' "$ts" "$nonce" "$sign"
}

# 服务端 IpFirewall 命中后的假成功（诱饵）: 结构正常但业务是假的
is_decoy() { grep -q '发送成功' <<<"$1" && grep -q '"data":null' <<<"$1"; }

extract_token() {
  local body="$1"
  if command -v jq >/dev/null 2>&1; then jq -r '.data.token // .data.userinfo.token // empty' <<<"$body"
  elif command -v python3 >/dev/null 2>&1; then python3 -c 'import sys,json;d=json.loads(sys.argv[1]);x=d.get("data") or {};print(x.get("token") or (x.get("userinfo") or {}).get("token") or "")' "$body"
  else grep -o '"token":"[^"]*"' <<<"$body" | head -1 | sed 's/.*"token":"\([^"]*\)".*/\1/'; fi
}

# 组装带鉴权头的 curl 参数 -> 全局数组 CURL_AUTH
# 注: lngLatToAddress 属 Map 控制器（noNeedLogin=['*']），默认不需要 token；
# 但 usertype 头是基类硬要求（非 1/2 直接「暂不支持该用户类型」），与登录与否无关
build_auth_args() {  # $1=query
  local q="$1" ts nonce sign
  CURL_AUTH=(-sS --max-time "$TIMEOUT" -H "usertype: $USERTYPE")
  if [ "$NEED_LOGIN" = "1" ] && [ -n "$TOKEN" ]; then
    CURL_AUTH+=(-H "token: $TOKEN")
  fi
  if [ "$PLATFORM" = "ios" ]; then
    IFS=$'\t' read -r ts nonce sign <<<"$(make_sign "$q")"
    CURL_AUTH+=(-H "platform: ios" -H "sign: $sign" -H "timestamp: $ts" -H "nonce: $nonce")
  else
    CURL_AUTH+=(-H "platform: web")
  fi
}

# 根据 REQ_METHOD 组装请求目标与 body -> 全局数组 CURL_REQ
# 签名串始络就是参数串本身（GET 放 query，POST 放 body），与后端
# http_build_query(ksort(request()->param())) 逐字一致，ios 才不会解签失败
build_req_args() {  # $1=query
  CURL_REQ=()
  if [ "$REQ_METHOD" = "GET" ]; then
    CURL_REQ+=("$BASE_URL$REGO_PATH?$1")
  else
    CURL_REQ+=(-X POST --data "$1" "$BASE_URL$REGO_PATH")
  fi
}

# ===================== 预检 =====================
command -v curl    >/dev/null 2>&1 || die "缺少 curl"
command -v openssl >/dev/null 2>&1 || die "缺少 openssl（签名依赖）"
[ "$PLATFORM" = "ios" ] && { [ -f "$PRIVATE_KEY" ] || die "找不到签名私钥: $PRIVATE_KEY"; }
BASE_URL="${BASE_URL%/}"

TMPDIR_RUN="$(mktemp -d)"
METRICS="$TMPDIR_RUN/metrics.txt"; : > "$METRICS"
# 全局计数/日志由 mkdir 自旋锁保护（macOS 无 flock），计数精确且日志不乱序
CNTD="$TMPDIR_RUN/cnt.done"; CNTS="$TMPDIR_RUN/cnt.succ"; CNTF="$TMPDIR_RUN/cnt.fail"
printf '0' > "$CNTD"; printf '0' > "$CNTS"; printf '0' > "$CNTF"
LOCKD="$TMPDIR_RUN/lock"
trap '[ "$KEEP_RESULTS" = "1" ] || rm -rf "$TMPDIR_RUN"' EXIT

acquire_lock() { while ! mkdir "$LOCKD" 2>/dev/null; do sleep 0.005; done; }
release_lock() { rmdir "$LOCKD" 2>/dev/null; }

say "模式: PLATFORM=$PLATFORM USERTYPE=$USERTYPE 登录态=$( [ "$NEED_LOGIN" = "1" ] && echo 需要 || echo 匿名 ) 目标=$BASE_URL$REGO_PATH"
[ "$PLATFORM" = "ios" ] && say "签名私钥: $PRIVATE_KEY"

# ===================== 步骤1: 登录取 token（NEED_LOGIN=0 时整个跳过） =====================
login_args=(-sS --max-time 10 -X POST "$BASE_URL$LOGIN_PATH" -H "usertype: $USERTYPE")
LOGIN_QUERY="$(build_query "account=$ACCOUNT" "jpush_reg_id=$JPUSH" "password=$PASSWORD")"
if [ "$PLATFORM" = "ios" ]; then
  IFS=$'\t' read -r LTS LNONCE LSIGN <<<"$(make_sign "$LOGIN_QUERY")"
  login_args+=(-H "platform: ios" -H "sign: $LSIGN" -H "timestamp: $LTS" -H "nonce: $LNONCE")
fi
login_args+=(--data-urlencode "account=$ACCOUNT" --data-urlencode "jpush_reg_id=$JPUSH" --data-urlencode "password=$PASSWORD")

if [ "$NEED_LOGIN" != "1" ]; then
  say "目标接口免登录（Map 控制器 noNeedLogin=['*']），跳过登录步骤：匿名请求，仅带 usertype 头"
elif [ -n "$TOKEN" ]; then
  say "使用外部传入的 token，跳过登录: ${TOKEN:0:8}****（长度 ${#TOKEN}）"
else
  try=0
  while :; do
    try=$((try + 1))
    say "登录(第${try}次): POST $BASE_URL$LOGIN_PATH"
    LOGIN_RESP="$(curl "${login_args[@]}" 2>/dev/null)" || die "登录请求失败（网络）"
    if is_decoy "$LOGIN_RESP"; then
      die "登录命中服务端 IP 防火墙假成功(发送成功!)，本机出口 IP 疑被封 24h。处理: 换出口IP / 服务器 redis-cli -n 6 DEL ipfirewall:block:<你的IP> / 等TTL。原始: ${LOGIN_RESP:0:200}"
    fi
    TOKEN="$(extract_token "$LOGIN_RESP")"
    [ -n "$TOKEN" ] && break

    lmsg="无"; [[ "$LOGIN_RESP" =~ \"msg\":\"([^\"]*)\" ]] && lmsg="${BASH_REMATCH[1]}"
    case "$lmsg" in
      *暴力请求*)
        # 登录接口被 WAF/边缘防暴力规则拦截（命中条件≈ path + account 值），不是应用行为：
        # 重试无用但可能是短窗口计数，退避重试几次；仍失败就换账号或改用 TOKEN 直传
        if [ "$try" -ge "$LOGIN_RETRY" ]; then
          die "登录被边缘防护拦截（${lmsg}）：该规则命中 /api/user/login + 该账号，与密码无关。解决（按成本排序）:
    1) 换一个可用账号: ACCOUNT=<未被打标的测试号> PASSWORD=<pwd> ./tests/amap_direct_regeo.sh
    2) 复用已有 token 跳过登录: TOKEN=<app登录后拿到的token> ./tests/amap_direct_regeo.sh
    3) 到服务器/面板把本机出口IP(curl ifconfig.me) 加入 WAF 白名单，或删掉 login 接口的防暴力规则
    4) 改打测试环境: BASE_URL=https://api.shanfly.com （实测无此规则）"
        fi
        wait_s=$((LOGIN_BACKOFF * try))
        warn "登录被边缘防护拦截（${lmsg}），退避 ${wait_s}s 后重试（第${try}/${LOGIN_RETRY}次）"
        sleep "$wait_s"
        ;;
      *)
        die "未能获取 token（msg=${lmsg}）。请确认账号存在且 user_type=$USERTYPE、status=normal。响应: ${LOGIN_RESP:0:300}"
        ;;
    esac
  done
  say "token 获取成功: ${TOKEN:0:8}****（长度 ${#TOKEN}）"
fi
[ "$NEED_LOGIN" = "1" ] && { [ -n "$TOKEN" ] || die "NEED_LOGIN=1 但 TOKEN 为空，无法发起带鉴权请求"; }

# ===================== 步骤2: 门禁探测（1 次请求判定链路是否真的通） =========
if [ "$GATE" = "1" ]; then
  GQ="$(build_query "$PARAM_LAT=$GATE_LAT" "$PARAM_LNG=$GATE_LNG")"
  build_auth_args "$GQ"
  say "门禁探测: $REQ_METHOD $BASE_URL$REGO_PATH  body/query=$GQ (固定国内坐标)"
  build_req_args "$GQ"
  GATE_RESP="$(curl "${CURL_AUTH[@]}" "${CURL_REQ[@]}" 2>/dev/null)" || die "门禁探测请求失败（网络）"
  if is_decoy "$GATE_RESP"; then
    die "门禁探测命中假成功(发送成功!) —— 本机出口 IP 被服务端 IpFirewall 封禁，压测无意义，请先解封。"
  fi
  if [[ "$GATE_RESP" == *'"code":1'* ]] && [[ "$GATE_RESP" == *'"data":{'* ]]; then
    if [[ "$GATE_RESP" =~ \"formatted_address\":\"[^\"] ]]; then
      say "门禁通过: 服务端高德链路正常且能解析出地址"
    else
      warn "门禁返回 code=1 但 formatted_address 为空——固定坐标不应为空，请核实 GATE_LNG/GATE_LAT 或 fa_map key 状态"
    fi
    printf '    %s\n' "${GATE_RESP:0:220}"
  else
    gmsg="无"; [[ "$GATE_RESP" =~ \"msg\":\"([^\"]*)\" ]] && gmsg="${BASH_REMATCH[1]}"
    die "门禁探测未拿到真实地址数据，压测数据将无效。msg=$gmsg
    响应: ${GATE_RESP:0:300}
    排查: msg=INVALID_USER_IP => fa_map 的 web_service key 未把服务器出口 IP 加入高德白名单（上服务器 curl ifconfig.me 取 IP 后加白）
          msg=暂不支持该用户类型 => 没带 usertype 头或值不是 1/2（基类硬校验）
          msg=经纬度格式不正确 => 坐标小数位不足 3 位，检查 LON_*/LAT_* 区间设置
          msg=高德API本月已用完 => fa_map 里 key 已全部被 markKeyUnavailable，需补 key 或等月初重置
          msg=高德API调用失败 => 逐个 key 轮换后无一成功，看服务端 runtime/log 里的 infocode
          msg=INVALID_USER_KEY/USERKEY_PLAT_NOMATCH => key 失效或平台类型不符
          msg=地址解析失败 => 高德 status=1 但无 formatted_address
          msg=请登录后操作 => 打到了需登录接口，需置 NEED_LOGIN=1
          msg=签名验证失败/请先升级客户端版本 => PLATFORM 与头不匹配；ios 必须带有效 sign+timestamp+nonce，
                且 platform=ios/android 而缺 sign 会被 IpFirewall 直接封 IP 24h（checkSign）
          跳过本门禁可设 GATE=0（不建议）"
  fi
else
  warn "已跳过门禁探测(GATE=0)，若链路不通将浪费全部线程与配额"
fi

# ===================== worker: 单请求 =====================
# metrics 一行: http_code|time_total|backend_code|dataflag(1/0)|decoy(Y/N)|msg|addr(1/0)
worker() {
  local seq="$1" q url raw tailline body http_code t bcode dataflag decoy msg ok resp lat lon
  gen_regeo_query
  q="$LAST_Q"; lat="$LAST_LAT"; lon="$LAST_LON"
  build_auth_args "$q"
  build_req_args "$q"
  raw="$(curl "${CURL_AUTH[@]}" "${CURL_REQ[@]}" -o - -w $'\n@@%{http_code}\t%{time_total}' 2>/dev/null)"
  # 解析尽量用 bash 内建，避免每请求 fork grep/sed/awk 拖低可达并发
  body="${raw%$'\n'*}"
  tailline="${raw##*$'\n'}"
  local hc="${tailline#@@}"
  http_code="${hc%%$'\t'*}"; t="${hc##*$'\t'}"
  [ -z "$http_code" ] && http_code="000"; [ -z "$t" ] && t="0"
  bcode="E"; [[ "$body" =~ \"code\":([0-9]) ]] && bcode="${BASH_REMATCH[1]}"
  dataflag=0; [[ "$body" == *'"data":{'* ]] && dataflag=1
  decoy="N"; [[ "$body" == *发送成功* && "$body" == *'"data":null'* ]] && decoy="Y"
  msg=""
  if [[ "$body" =~ \"msg\":\"([^\"]*)\" ]]; then msg="${BASH_REMATCH[1]//|/ }"; msg="${msg//$'\r'/}"; fi
  # addr=1 表示真解析出地址; lngLatToAddress 仅在高德 status=1 且 formatted_address 非空时返回 code=1
  addr=0; [[ "$body" =~ \"formatted_address\":\"[^\"] ]] && addr=1
  printf '%s|%s|%s|%s|%s|%s|%s\n' "$http_code" "$t" "$bcode" "$dataflag" "$decoy" "${msg:-无}" "$addr" >> "$METRICS"
  # ---- 每请求实时日志（加锁：计数精确、输出不乱序，含完整响应体） ----
  if [ "$http_code" = "200" ] && [ "$bcode" = "1" ] && [ "$dataflag" = "1" ] && [ "$decoy" = "N" ]; then ok=1; else ok=0; fi
  resp="${body//$'\r'/}"; resp="${resp//$'\n'/}"
  acquire_lock
  local done_n succ_n fail_n
  done_n=$(($(cat "$CNTD") + 1)); succ_n=$(cat "$CNTS"); fail_n=$(cat "$CNTF")
  if [ "$ok" = "1" ]; then
    succ_n=$((succ_n + 1))
    printf '[#%s] \033[1;32m成功\033[0m | %ss | 坐标=%s,%s | %s | 累计: 第%s次 成功%s 失败%s | 响应=%s\n' \
      "$seq" "$t" "$lon" "$lat" "$([ "$addr" = 1 ] && printf '已解析' || printf '空结果(海面/境外)')" "$done_n" "$succ_n" "$fail_n" "${resp:-无响应体}"
    printf '%s' "$succ_n" > "$CNTS"
  else
    fail_n=$((fail_n + 1))
    printf '[#%s] \033[1;31m失败\033[0m(http=%s code=%s msg=%s) | %ss | 坐标=%s,%s | 累计: 第%s次 成功%s 失败%s | 响应=%s\n' \
      "$seq" "$http_code" "$bcode" "${msg:-无}" "$t" "$lon" "$lat" "$done_n" "$succ_n" "$fail_n" "${resp:-无响应体}"
    printf '%s' "$fail_n" > "$CNTF"
  fi
  printf '%s' "$done_n" > "$CNTD"
  release_lock
}
export -f worker build_auth_args build_req_args gen_regeo_query build_query make_sign gen_nonce now_s is_decoy \
        acquire_lock release_lock
export BASE_URL TOKEN METRICS TIMEOUT USERTYPE PLATFORM PRIVATE_KEY REGO_PATH JPUSH NEED_LOGIN \
       REQ_METHOD PARAM_LNG PARAM_LAT LON_MIN LON_MAX LAT_MIN LAT_MAX CNTD CNTS CNTF LOCKD

# ===================== 执行: 限速 + 定时 + 限并发 =====================
INTERVAL="$(awk -v r="$RATE" 'BEGIN{printf "%.4f", (r>0)?1/r:1}')"
PLANNED=$(( RATE * DURATION ))
say "开始压测: 并发≤$CONCURRENCY, 全局限速 ${RATE} req/s, 持续 ${DURATION}s (计划≈${PLANNED} 次)"
say "注意: 每个请求都会真实调用一次高德逆地理编码并消耗服务端配额"

# 模型: 每 INTERVAL 秒发起一个后台请求; 在途达到 CONCURRENCY 则先等 -> 既限速又限并发
START="$(now)"
n=0; SECONDS=0
while (( SECONDS < DURATION )); do
  while (( $(jobs -rp | wc -l) >= CONCURRENCY )); do sleep 0.02; done
  n=$((n + 1))
  ( worker "$n" ) &
  sleep "$INTERVAL"
done
wait                     # 等所有在途请求完成
END="$(now)"
WALL="$(awk -v a="$START" -v b="$END" 'BEGIN{printf "%.3f", b-a}')"

# ===================== 统计 =====================
TOTAL="$n"
HTTP200=$(awk -F'|' '$1=="200"' "$METRICS" | wc -l | tr -d ' ')
NON200=$(awk -F'|' '$1!="200"' "$METRICS" | wc -l | tr -d ' ')
DECOY=$(awk -F'|' '$5=="Y"' "$METRICS" | wc -l | tr -d ' ')
OK=$(awk -F'|' '$1=="200" && $5=="N" && $3=="1" && $4=="1"' "$METRICS" | wc -l | tr -d ' ')
BIZFAIL=$(awk -F'|' '$1=="200" && $5=="N" && ($3!="1" || $4!="1")' "$METRICS" | wc -l | tr -d ' ')

printf '\n================= 结果 (后端 %s) =================\n' "$REGO_PATH"
printf '总请求=%s  HTTP200=%s  成功(code1&有data)=%s  业务失败/无数据=%s  非200=%s  假成功(封禁诱饵)=%s\n' \
  "$TOTAL" "$HTTP200" "$OK" "$BIZFAIL" "$NON200" "$DECOY"
awk -v t="$TOTAL" -v w="$WALL" 'BEGIN{if(w>0)printf "整体QPS≈%.1f req/s  墙钟=%.2fs\n", t/w, w}'
[ "$TOTAL" -gt 0 ] && awk -v o="$OK" -v t="$TOTAL" 'BEGIN{printf "成功率=%.2f%%\n", o*100/t}'

# 成功样本延迟（真实反映高德耗时；失败样本是网关秒拒，混进来会拉低均值造成误判）
printf '\n---- 成功样本延迟（仅 code=1 且有数据） ----\n'
awk -F'|' '$1=="200" && $5=="N" && $3=="1" && $4=="1"{a[n++]=$2; if($7==1)hit++; else empty++} END{
  if(n==0){print "  无成功样本"; exit}
  for(i=0;i<n;i++)for(j=i+1;j<n;j++)if(a[j]<a[i]){x=a[i];a[i]=a[j];a[j]=x}
  s=0;for(i=0;i<n;i++)s+=a[i]
  printf "  min=%.3fs avg=%.3fs p50=%.3fs p95=%.3fs max=%.3fs (n=%d)\n", a[0], s/n, a[int((n-1)*0.5)], a[int((n-1)*0.95)], a[n-1], n
  printf "  其中 已解析出地址=%d  空结果(海面/境外)=%d —— 空结果占比过高时延迟偏低, 请收窄坐标范围\n", hit+0, empty+0}' "$METRICS"

printf '\n---- 后端 code 分布 ----\n'
awk -F'|' '{printf "code=%s\n",$3}' "$METRICS" | sort | uniq -c | sort -rn \
| awk '{c=$1;$1="";printf "  x%-5s%s\n", c, substr($0,2)}'

printf '\n---- msg 分布（含高德错误码，Top15） ----\n'
ms=$(awk -F'|' '$5=="N" && ($3!="1" || $4!="1"){print $6}' "$METRICS" | sort | uniq -c | sort -rn | head -15 \
| awk '{c=$1;$1="";printf "  x%-5s%s\n", c, substr($0,2)}')
[ -n "$ms" ] && printf '%s\n' "$ms" || echo "  (无失败)"

printf '\n---- 非200 明细 ----\n'
n2=$(awk -F'|' '$1!="200"{print $1}' "$METRICS" | sort | uniq -c | sort -rn \
| awk '{c=$1;printf "  x%-5s http=%s\n", c, $2}')
[ -n "$n2" ] && printf '%s\n' "$n2" || echo "  (无)"

printf '\n[+] 判读要点:\n'
printf '  - 成功样本 avg 才是服务端+高德的真实耗时；与直连高德的差值≈后端框架+鉴权开销\n'
printf '  - 想测"重数据"耗时: 收窄 LON_MIN/LON_MAX/LAT_MIN/LAT_MAX 到城市密集区(如 113~121 / 22~40)\n'
printf '  - msg=INVALID_USER_IP 成批出现 => fa_map 的 web_service key 未白名单服务器出口 IP（生产同样会挂）\n'
printf '  - msg=高德API本月已用完 => key 池配额打光，本接口会整体验证失败，降 RATE 或补 key\n'
printf '  - 大量非200 或 time≈TIMEOUT => 已达服务端/PHP-FPM/DB 并发上限，降档 RATE 找拐点\n'
printf '  - 成功率低但都是限流类 msg(10021/10014/10010) => 撞到高德阈值，需降 RATE 或提配额\n'
[ "$DECOY" -gt 0 ] && warn "出现 $DECOY 个假成功 => 本机 IP 已被服务端 IpFirewall 封禁，本轮数据作废！"
[ "$OK" -eq 0 ] && warn "无一个成功样本，请先按上面的 msg 分布定位链路问题，不要看延迟"
exit 0
