#!/usr/bin/env bash
###############################################################################
# amap_direct_regeo.sh —— 逆地理编码压测（走后端 /api/common/getRegeo）
#
# 为什么改: 原「直连 restapi.amap.com」模式已失效 —— 后端 /api/index/getMap 下发的
#   web_service key 在高德侧启用了 IP 白名单校验，非白名单出口 IP 会 100% 返回
#   infocode=10005 INVALID_USER_IP（实测正式 8a44283c... 与测试 26372cfa... 两个 key
#   均如此），压测拿到的全是网关秒拒的无效数据。
#   改为请求后端接口后：高德调用发生在服务器侧（用 .env 的 [map] key），既验证了
#   真实业务链路，也把「服务端 key 是否被白名单挡住」这个生产风险直接暴露出来。
#
# 流程:
#   1) 登录取 token（默认 platform:web，不触发签名校验与 IP 防火墙）
#   2) 门禁探测：先单发 1 次，非成功结构立即终止并给出诊断，不把线程和配额
#      浪费在必然失败的请求上（SKIP_GATE=1 可跳过）
#   3) 限速 + 限并发持续 DURATION 秒，每个请求经纬度随机
#   4) 统计成功率、延迟分位、后端 code 分布、msg（含高德错误码）分布
#
# 用法:
#   ./tests/amap_direct_regeo.sh
#   CONCURRENCY=8 RATE=5 DURATION=600 ./tests/amap_direct_regeo.sh
#   RATE=6 DURATION=6 ./tests/amap_direct_regeo.sh            # 先跑6秒快速验证
#   PLATFORM=ios ./tests/amap_direct_regeo.sh                 # 还原 App 真实签名链路
#   BASE_URL=https://api.shanfly.com ACCOUNT=x PASSWORD=y ./tests/amap_direct_regeo.sh
#
# 判读（HTTP 200 不代表成功，以 JSON 内 code / msg 为准）:
#   code=1 且 data.addressComponent 存在 => 高德真实返回，延迟数据可信
#   msg=INVALID_USER_IP      => 服务端出口 IP 不在高德 key 的 IP 白名单内（需上服务器加白名单）
#   msg=INVALID_USER_KEY / USERKEY_PLAT_NOMATCH => key 失效或平台类型不符
#   msg=CUQPS_HAS_EXCEEDED_THE_LIMIT / QPS...    => 高德并发或配额受限（10021/10014 等）
#   msg=获取失败             => 服务端没拿到高德响应或响应非 JSON（网络/超时）
#   {"code":1,"msg":"发送成功!"} 假成功 => 本机出口 IP 被服务端 IpFirewall 封禁 24h
###############################################################################
set -uo pipefail

# ===================== 可配置参数 =====================
BASE_URL="${BASE_URL:-https://sdfgdfss.shanfly.com}"     # 正式环境; api.shanfly.com=测试
ACCOUNT="${ACCOUNT:-13594019185}"                        # 登录手机号（须与 USERTYPE 匹配）
PASSWORD="${PASSWORD:-123456}"
JPUSH="${JPUSH_REG_ID:-}"                                # 极光 registrationId（无则留空）
USERTYPE="${USERTYPE:-1}"                                # 1=用户端 2=飞手端
PLATFORM="${PLATFORM:-web}"                              # web=明文(默认, 并发上限最高) | ios=逐请求签名(还原App链路)
PRIVATE_KEY="${PRIVATE_KEY:-$(cd "$(dirname "$0")/.." && pwd)/storage/verify/private.pem}"
LOGIN_PATH="${LOGIN_PATH:-/api/user/login}"
REGO_PATH="${REGO_PATH:-/api/common/getRegeo}"           # 后端逆地理编码入口

CONCURRENCY="${CONCURRENCY:-10}"                         # 常驻并发上限
RATE="${RATE:-10}"                                       # 全局限速 req/s（注意会真实消耗高德配额）
DURATION="${DURATION:-1200}"                               # 持续时长(秒)
TIMEOUT="${TIMEOUT:-5}"                                  # 单请求超时秒
LON_MIN="${LON_MIN:-73}"; LON_MAX="${LON_MAX:-135}"      # 经度范围(中国大陆)
LAT_MIN="${LAT_MIN:-18}"; LAT_MAX="${LAT_MAX:-53}"       # 纬度范围
GATE="${GATE:-1}"                                        # 1=开跑前门禁探测; 0=跳过
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
gen_regeo_query() {
  local r hi lo lon lat
  r="$(openssl rand -hex 8)"
  hi=$((16#${r:0:8})); lo=$((16#${r:8:8}))
  lon="$(awk -v h="$hi" -v a="$LON_MIN" -v b="$LON_MAX" 'BEGIN{printf "%.6f", a+(b-a)*(h/4294967295)}')"
  lat="$(awk -v h="$lo" -v a="$LAT_MIN" -v b="$LAT_MAX" 'BEGIN{printf "%.6f", a+(b-a)*(h/4294967295)}')"
  build_query "latitude=$lat" "longitude=$lon"
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
build_auth_args() {  # $1=query
  local q="$1" ts nonce sign
  CURL_AUTH=(-sS --max-time "$TIMEOUT" -H "token: $TOKEN" -H "usertype: $USERTYPE")
  if [ "$PLATFORM" = "ios" ]; then
    IFS=$'\t' read -r ts nonce sign <<<"$(make_sign "$q")"
    CURL_AUTH+=(-H "platform: ios" -H "sign: $sign" -H "timestamp: $ts" -H "nonce: $nonce")
  else
    CURL_AUTH+=(-H "platform: web")
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

say "模式: PLATFORM=$PLATFORM USERTYPE=$USERTYPE 目标=$BASE_URL$REGO_PATH"
[ "$PLATFORM" = "ios" ] && say "签名私钥: $PRIVATE_KEY"

# ===================== 步骤1: 登录取 token =====================
LOGIN_QUERY="$(build_query "account=$ACCOUNT" "jpush_reg_id=$JPUSH" "password=$PASSWORD")"
login_args=(-sS --max-time 10 -X POST "$BASE_URL$LOGIN_PATH" -H "usertype: $USERTYPE")
if [ "$PLATFORM" = "ios" ]; then
  IFS=$'\t' read -r LTS LNONCE LSIGN <<<"$(make_sign "$LOGIN_QUERY")"
  login_args+=(-H "platform: ios" -H "sign: $LSIGN" -H "timestamp: $LTS" -H "nonce: $LNONCE")
fi
login_args+=(--data-urlencode "account=$ACCOUNT" --data-urlencode "jpush_reg_id=$JPUSH" --data-urlencode "password=$PASSWORD")
say "登录: POST $BASE_URL$LOGIN_PATH"
LOGIN_RESP="$(curl "${login_args[@]}" 2>/dev/null)" || die "登录请求失败（网络）"
if is_decoy "$LOGIN_RESP"; then
  die "登录命中服务端 IP 防火墙假成功(发送成功!)，本机出口 IP 疑被封 24h。处理: 换出口IP / 服务器 redis-cli -n 6 DEL ipfirewall:block:<你的IP> / 等TTL。原始: ${LOGIN_RESP:0:200}"
fi
TOKEN="$(extract_token "$LOGIN_RESP")"
[ -n "$TOKEN" ] || die "未能获取 token。响应: ${LOGIN_RESP:0:300}"
say "token 获取成功: ${TOKEN:0:8}****（长度 ${#TOKEN}）"

# ===================== 步骤2: 门禁探测（1 次请求判定链路是否真的通） =========
if [ "$GATE" = "1" ]; then
  GQ="$(gen_regeo_query)"
  build_auth_args "$GQ"
  say "门禁探测: GET $BASE_URL$REGO_PATH?$GQ"
  GATE_RESP="$(curl "${CURL_AUTH[@]}" "$BASE_URL$REGO_PATH?$GQ" 2>/dev/null)" || die "门禁探测请求失败（网络）"
  if is_decoy "$GATE_RESP"; then
    die "门禁探测命中假成功(发送成功!) —— 本机出口 IP 被服务端 IpFirewall 封禁，压测无意义，请先解封。"
  fi
  if [[ "$GATE_RESP" == *'"code":1'* ]] && [[ "$GATE_RESP" == *'"data":{'* ]]; then
    say "门禁通过: 服务端高德链路正常（成功样本，响应截断展示）"
    printf '    %s\n' "${GATE_RESP:0:220}"
  else
    gmsg="无"; [[ "$GATE_RESP" =~ \"msg\":\"([^\"]*)\" ]] && gmsg="${BASH_REMATCH[1]}"
    die "门禁探测未拿到真实地址数据，压测数据将无效。msg=$gmsg
    响应: ${GATE_RESP:0:300}
    排查: msg=INVALID_USER_IP => 服务器出口 IP 不在高德 key 白名单（上服务器执行 curl ifconfig.me 取 IP 后加白名单）
          msg=INVALID_USER_KEY/USERKEY_PLAT_NOMATCH => .env 的 [map] key 失效或平台类型不符
          msg=获取失败 => 服务器到高德的网络问题，查 runtime/log 里的 regeo-error/regeo-info
          跳过本门禁可设 GATE=0（不建议）"
  fi
else
  warn "已跳过门禁探测(GATE=0)，若链路不通将浪费全部线程与配额"
fi

# ===================== worker: 单请求 =====================
# metrics 一行: http_code|time_total|backend_code|dataflag(1/0)|decoy(Y/N)|msg|addr(1/0)
worker() {
  local seq="$1" q url raw tailline body http_code t bcode dataflag decoy msg ok resp lat lon
  q="$(gen_regeo_query)"
  lat="${q#latitude=}"; lat="${lat%%&*}"; lon="${q##*longitude=}"
  url="$BASE_URL$REGO_PATH?$q"
  build_auth_args "$q"
  raw="$(curl "${CURL_AUTH[@]}" -o - -w $'\n@@%{http_code}\t%{time_total}' "$url" 2>/dev/null)"
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
  # addr=1 表示真解析出地址; 随机点落到海面/境外时高德会返回空结构(仍算成功但延迟偏低)
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
export -f worker build_auth_args gen_regeo_query build_query make_sign gen_nonce now_s is_decoy \
        acquire_lock release_lock
export BASE_URL TOKEN METRICS TIMEOUT USERTYPE PLATFORM PRIVATE_KEY REGO_PATH JPUSH \
       LON_MIN LON_MAX LAT_MIN LAT_MAX CNTD CNTS CNTF LOCKD

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

printf '\n================= 结果 (后端 /api/common/getRegeo) =================\n'
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
printf '  - 成功样本 avg 才是服务端+高德的真实耗时；与直连高德的差值≈后端框架+登录鉴权开销\n'
printf '  - 想测"重数据"耗时: 收窄 LON_MIN/LON_MAX/LAT_MIN/LAT_MAX 到城市密集区(如 113~121 / 22~40)\n'
printf '  - msg=INVALID_USER_IP 成批出现 => 服务器出口 IP 未进高德 key 白名单（生产同样会挂）\n'
printf '  - 大量非200 或 time≈TIMEOUT => 已达服务端/PHP-FPM/DB 并发上限，降档 RATE 找拐点\n'
printf '  - 成功率低但都是限流类 msg(10021/10014/10010) => 撞到高德阈值，需降 RATE 或提配额\n'
[ "$DECOY" -gt 0 ] && warn "出现 $DECOY 个假成功 => 本机 IP 已被服务端 IpFirewall 封禁，本轮数据作废！"
[ "$OK" -eq 0 ] && warn "无一个成功样本，请先按上面的 msg 分布定位链路问题，不要看延迟"
exit 0
