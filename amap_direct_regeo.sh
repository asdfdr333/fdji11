#!/usr/bin/env bash
###############################################################################
# amap_direct_regeo.sh —— 直连高德逆地理编码压测
#
# 流程:
#   1) 调后端 /api/index/getMap 取 web_service 高德 key (免登录/免签名, 用 platform:web 避开IP防火墙)
#   2) 用该 key 直接请求高德 https://restapi.amap.com/v3/geocode/regeo
#   3) 随机不同经纬度, 执行 CALLS 次(默认100), 统计高德 status/infocode 与延迟
#
# 用法 (默认: 3 线程并发 / 全局限速 10 req/s / 连续 30 分钟):
#   ./tests/amap_direct_regeo.sh
#   CONCURRENCY=3 RATE=10 DURATION=1800 ./tests/amap_direct_regeo.sh
#   DURATION=6 RATE=10 ./tests/amap_direct_regeo.sh   # 先跑6秒快速验证
#   BASE_URL=https://api.shanfly.com ./tests/amap_direct_regeo.sh   # 换环境取key
#
# 判读(高德 infocode, 以响应 info 字段为准):
#   10000 OK 成功 | 10021 CUQPS_HAS_EXCEEDED_THE_LIMIT(并发超限) | 10004/10014 日/用量超限
#   10001 INVALID_USER_KEY(key无效) | 10003 无权限/服务不可用 | 10010 签名不匹配 | 10019 缺少必选参数
###############################################################################
set -uo pipefail

# ===================== 可配置参数 =====================
BASE_URL="${BASE_URL:-https://sdfgdfss.shanfly.com}"   # 取key的后端地址(正式=sdfgdfss, 测试=api.shanfly.com)
GETMAP_PATH="${GETMAP_PATH:-/api/index/getMap}"
AMAP_URL="${AMAP_URL:-https://restapi.amap.com/v3/geocode/regeo}"
USERTYPE="${USERTYPE:-1}"                             # getMap 的 usertype 头(选择地图配置)
PLATFORM_HDR="${PLATFORM_HDR:-web}"                   # 取key用的 platform 头; web=不触发签名与IP防火墙
EXTENSIONS="${EXTENSIONS:-all}"                       # 高德 extensions: base|all
CALLS="${CALLS:-100}"                                 # (已废弃: 仅保留兼容; 实际总量由 RATE*DURATION 决定)
CONCURRENCY="${CONCURRENCY:-10}"                       # 常驻并发线程数
RATE="${RATE:-10}"                                     # 全局限速: 每秒发起请求数
DURATION="${DURATION:-36000}"                          # 持续时长(秒); 1800=30分钟
TIMEOUT="${TIMEOUT:-5}"                               # 单请求超时秒
LON_MIN="${LON_MIN:-73}"; LON_MAX="${LON_MAX:-135}"   # 经度范围(中国大陆)
LAT_MIN="${LAT_MIN:-18}"; LAT_MAX="${LAT_MAX:-53}"    # 纬度范围
KEEP_RESULTS="${KEEP_RESULTS:-0}"

say()  { printf '\033[1;36m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
now() { if command -v perl >/dev/null 2>&1; then perl -MTime::HiRes=time -e 'printf "%.6f", time'; else date +%s; fi; }

# 随机经纬度, 输出 "lon lat"
gen_location() {
  local r hi lo lon lat
  r="$(openssl rand -hex 8)"
  hi=$((16#${r:0:8})); lo=$((16#${r:8:8}))
  lon="$(awk -v h="$hi" -v a="$LON_MIN" -v b="$LON_MAX" 'BEGIN{printf "%.6f", a+(b-a)*(h/4294967295)}')"
  lat="$(awk -v h="$lo" -v a="$LAT_MIN" -v b="$LAT_MAX" 'BEGIN{printf "%.6f", a+(b-a)*(h/4294967295)}')"
  printf '%s %s' "$lon" "$lat"
}

extract_key() {  # $1=json
  if command -v jq >/dev/null 2>&1; then
    jq -r '.data.keys.web_service.map_key // empty' <<<"$1" 2>/dev/null
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys,json;d=json.loads(sys.argv[1]);print(((d.get("data") or {}).get("keys") or {}).get("web_service",{}).get("map_key","") or "")' "$1" 2>/dev/null
  else
    grep -o '"web_service"[^}]*"map_key":"[^"]*"' <<<"$1" | grep -o '"map_key":"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/'
  fi
}

command -v curl    >/dev/null 2>&1 || die "缺少 curl"
command -v openssl >/dev/null 2>&1 || die "缺少 openssl"

# ===================== 步骤1: 获取高德 web_service key =====================
say "取 key: GET $BASE_URL$GETMAP_PATH (usertype=$USERTYPE platform=$PLATFORM_HDR)"
MAP_RESP="$(curl -sS --max-time 10 -H "usertype: $USERTYPE" -H "platform: $PLATFORM_HDR" "$BASE_URL$GETMAP_PATH" 2>/dev/null)" || die "getMap 请求失败(网络)"
if grep -q '发送成功' <<<"$MAP_RESP" && grep -q '"data":null' <<<"$MAP_RESP"; then
  die "getMap 命中防火墙假成功(发送成功!), 说明当前出口IP可能已被封。请换IP或用 platform:web 重试。原始: ${MAP_RESP:0:200}"
fi
AMAP_KEY="$(extract_key "$MAP_RESP")"
[ -n "$AMAP_KEY" ] || die "未能解析 web_service key。响应: ${MAP_RESP:0:400}"
say "高德 web_service key: ${AMAP_KEY:0:6}****（长度 ${#AMAP_KEY}）"

# ===================== 临时目录 & worker =====================
TMPDIR_RUN="$(mktemp -d)"; METRICS="$TMPDIR_RUN/metrics.txt"; : > "$METRICS"
# 全局计数/日志由 mkdir 自旋锁保护(macOS无flock), 计数精确且日志不乱序
CNTD="$TMPDIR_RUN/cnt.done"; CNTS="$TMPDIR_RUN/cnt.succ"; CNTF="$TMPDIR_RUN/cnt.fail"
printf '0' > "$CNTD"; printf '0' > "$CNTS"; printf '0' > "$CNTF"
LOCKD="$TMPDIR_RUN/lock"
trap '[ "$KEEP_RESULTS" = "1" ] || rm -rf "$TMPDIR_RUN"' EXIT

acquire_lock() { while ! mkdir "$LOCKD" 2>/dev/null; do sleep 0.005; done; }
release_lock() { rmdir "$LOCKD" 2>/dev/null; }

# 记录一行: http_code|time|status|infocode|info|has_addr|坐标|序号|响应体; $1=本次请求序号(主循环分配)
worker() {
  local seq="$1" loc lon lat body raw tailline http_code t status infocode info addr ok resp
  loc="$(gen_location)"; lon="${loc%% *}"; lat="${loc##* }"
  raw="$(curl -sS --max-time "$TIMEOUT" -o - -w $'\n@@%{http_code}\t%{time_total}' \
      "$AMAP_URL?key=$AMAP_KEY&location=$lon,$lat&extensions=$EXTENSIONS" 2>/dev/null)"
  tailline="${raw##*$'\n'}"; body="${raw%$'\n'*}"
  http_code="${tailline#@@}"; http_code="${http_code%%$'\t'*}"
  t="${tailline##*$'\t'}"
  [ -z "$http_code" ] && http_code="000"; [ -z "$t" ] && t="0"
  status=""; infocode=""; info=""; addr=0
  [[ "$body" =~ \"status\":\"([^\"]*)\" ]]  && status="${BASH_REMATCH[1]}"
  [[ "$body" =~ \"infocode\":\"([^\"]*)\" ]] && infocode="${BASH_REMATCH[1]}"
  [[ "$body" =~ \"info\":\"([^\"]*)\" ]]     && info="${BASH_REMATCH[1]}"
  [[ "$body" == *formatted_address* ]]       && addr=1
  printf '%s|%s|%s|%s|%s|%s\n' "$http_code" "$t" "${status:-E}" "${infocode:-E}" "${info:-无}" "$addr" >> "$METRICS"
  # ---- 每次请求日志(加锁: 计数精确、输出不乱序) ----
  if [ "$http_code" = "200" ] && [ "${status:-E}" = "1" ] && [ "${infocode:-E}" = "10000" ]; then ok=1; else ok=0; fi
  resp="${body//$'\r'/}"; resp="${resp//$'\n'/}"   # 压成单行, 避免日志错乱
  acquire_lock
  local done_n succ_n fail_n
  done_n=$(($(cat "$CNTD") + 1)); succ_n=$(cat "$CNTS"); fail_n=$(cat "$CNTF")
  if [ "$ok" = "1" ]; then
    succ_n=$((succ_n + 1))
    printf '[#%s] \033[1;32m成功\033[0m | %ss | 坐标=%s,%s | 累计: 第%s次 成功%s 失败%s | 响应=%s\n' \
      "$seq" "$t" "$lon" "$lat" "$done_n" "$succ_n" "$fail_n" "${resp:-无响应体}"
    printf '%s' "$succ_n" > "$CNTS"
  else
    fail_n=$((fail_n + 1))
    printf '[#%s] \033[1;31m失败\033[0m(http=%s infocode=%s) | %ss | 坐标=%s,%s | 累计: 第%s次 成功%s 失败%s | 响应=%s\n' \
      "$seq" "$http_code" "${infocode:-E}" "$t" "$lon" "$lat" "$done_n" "$succ_n" "$fail_n" "${resp:-无响应体}"
    printf '%s' "$fail_n" > "$CNTF"
  fi
  printf '%s' "$done_n" > "$CNTD"
  release_lock
}
export -f worker gen_location now acquire_lock release_lock
export AMAP_URL AMAP_KEY EXTENSIONS TIMEOUT METRICS CNTD CNTS CNTF LOCKD LON_MIN LON_MAX LAT_MIN LAT_MAX

# ===================== 执行: 限速 + 定时 + 限制并发 =====================
INTERVAL="$(awk -v r="$RATE" 'BEGIN{printf "%.4f", (r>0)?1/r:1}')"
PLANNED=$(( RATE * DURATION ))
say "直连高德 regeo: 并发≤$CONCURRENCY, 全局限速 ${RATE} req/s, 持续 ${DURATION}s (计划≈${PLANNED} 次), extensions=$EXTENSIONS"

# 模型: 每 INTERVAL 秒发起一个后台请求; 在途达到 CONCURRENCY 列先等 -> 既限速又限并发
START="$(now)"
n=0; SECONDS=0
while (( SECONDS < DURATION )); do
  while (( $(jobs -rp | wc -l) >= CONCURRENCY )); do sleep 0.02; done
  n=$((n+1))
  ( worker "$n" ) &
  sleep "$INTERVAL"
done
wait                    # 等所有在途请求完成
END="$(now)"
WALL="$(awk -v a="$START" -v b="$END" 'BEGIN{printf "%.3f", b-a}')"

# ===================== 统计 =====================
TOTAL="$n"
OK=$(awk -F'|' '$1=="200" && $3=="1" && $4=="10000"' "$METRICS" | wc -l | tr -d ' ')
NON200=$(awk -F'|' '$1!="200"' "$METRICS" | wc -l | tr -d ' ')

printf '\n================= 结果 (直连高德) =================\n'
printf '总请求=%s  成功(status1&infocode10000)=%s  非200=%s\n' "$TOTAL" "$OK" "$NON200"
awk -v t="$TOTAL" -v w="$WALL" 'BEGIN{if(w>0)printf "整体QPS≈%.1f req/s  墙钟=%.2fs\n", t/w, w}'

# 仅统计 HTTP200 的延迟
awk -F'|' '$1=="200"{a[n++]=$2} END{
  if(n==0){print "延迟: 无样本"; exit}
  for(i=0;i<n;i++)for(j=i+1;j<n;j++)if(a[j]<a[i]){x=a[i];a[i]=a[j];a[j]=x}
  s=0;for(i=0;i<n;i++)s+=a[i]
  printf "延迟: min=%.3fs avg=%.3fs p95=%.3fs max=%.3fs\n", a[0], s/n, a[int((n-1)*0.95)], a[n-1]}' "$METRICS"

printf '\n---- status / infocode / info 分布 ----\n'
awk -F'|' '$1=="200"{printf "status=%s infocode=%s info=%s  x1\n",$3,$4,$5}' "$METRICS" \
| sort | uniq -c | sort -rn \
| awk '{c=$1;$1="";printf "  x%-5s%s\n", c, substr($0,2)}'

[ "$NON200" -gt 0 ] && { echo; warn "有 $NON200 个非200(高德请求未拿到HTTP响应, 多为网络/超时), 记为 code=000"; }

printf '\n[+] 判读(以 info 为准): infocode=10000 才算成功; 10021=并发(CUQPS)超限, 10004/10014=日/用量耗尽, 10001/10003=key无效或无权限\n'
exit 0
