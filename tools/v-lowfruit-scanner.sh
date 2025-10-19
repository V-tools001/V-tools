#!/usr/bin/env bash
# ===============================================================
#  V-lowFruit Scanner 🍏 — by Veron  (part of V-tools)
#  @desc: quick scanner for low-hanging web misconfigurations
#  ---------------------------------------------------------------
#  This tool is FREE to use and modify — ONLY for educational use
#  and lawful, authorized security testing. By using this tool,
#  you agree you have explicit permission to test the target.
# ===============================================================

set -euo pipefail

TARGET_RAW="${1:-}"
if [[ -z "${TARGET_RAW}" || "${TARGET_RAW}" =~ ^(-h|--help)$ ]]; then
  cat <<'HLP'
V-lowFruit Scanner 🍏 — by Veron

Usage:
  v lowfruit-scanner https://example.com

Notes:
  - Read-only checks: headers, CORS, cookies, sensitive files, errors, etc.
  - Educational & authorized testing ONLY.
HLP
  exit 0
fi

# ---------- helpers ----------
norm_host() { local in="$1"; in="${in#http://}"; in="${in#https://}"; in="${in%%/*}"; echo "$in"; }
abs_url()    { local base="$1" path="$2"; [[ "$path" =~ ^https?:// ]] && echo "$path" && return; echo "https://$(norm_host "$base")/${path#/}"; }
hr()         { printf '%*s\n' "${COLUMNS:-80}" '' | tr ' ' '-'; }
say()        { printf "\n\033[1m%s\033[0m\n" "$*"; }
ok()         { printf "  ✅ %s\n" "$*"; }
warn()       { printf "  ⚠️  %s\n" "$*"; }
bad()        { printf "  ❌ %s\n" "$*"; }
info()       { printf "  • %s\n" "$*"; }

H="$(norm_host "$TARGET_RAW")"
HTTPS="https://${H}"
HTTP="http://${H}"

hr
say "🍏 V-lowFruit Scanner — by Veron (V-tools)"
say "Target: ${HTTPS}"
hr

# 1) security headers
say "1) Security headers"
HDRS="$(curl -s -D- -o /dev/null -L --http2 "${HTTPS}" 2>/dev/null || true)"
shopt -s nocasematch
declare -A WANT=(
  ["content-security-policy"]="CSP"
  ["permissions-policy"]="Permissions-Policy"
  ["strict-transport-security"]="HSTS"
  ["x-content-type-options"]="X-Content-Type-Options"
  ["x-frame-options"]="X-Frame-Options"
  ["referrer-policy"]="Referrer-Policy"
  ["cross-origin-opener-policy"]="COOP"
  ["cross-origin-embedder-policy"]="COEP"
  ["cross-origin-resource-policy"]="CORP"
)
for k in "${!WANT[@]}"; do
  if grep -qi "^${k}:" <<<"$HDRS"; then ok "${WANT[$k]} present"
  else warn "${WANT[$k]} missing"
  fi
done
shopt -u nocasematch

# 2) HTTP → HTTPS behavior
say "2) HTTP → HTTPS behavior"
RES_HTTP="$(curl -s -D- -o /dev/null -L --http1.1 -H "User-Agent: Mozilla/5.0" -H "Accept: text/html" "${HTTP}" || true)"
if grep -qi '^http/.* 301\|^http/.* 308' <<<"$RES_HTTP"; then
  ok "HTTP redirects to HTTPS"
elif grep -qi '^http/.* 403' <<<"$RES_HTTP"; then
  warn "HTTP responds 403 (no redirect enforced)"
else
  warn "Unexpected HTTP response (check manually)"
  echo "$RES_HTTP" | sed -n '1,10p'
fi

# 3) CORS quick tests
say "3) CORS quick tests"
C1="$(curl -s -I -H 'Origin: https://evil.com' "${HTTPS}" 2>/dev/null || true)"
C2="$(curl -s -I -H 'Origin: null' "${HTTPS}" 2>/dev/null || true)"
C3="$(curl -s -i -X OPTIONS -H 'Origin: https://evil.com' -H 'Access-Control-Request-Method: GET' "${HTTPS}" 2>/dev/null || true)"
if grep -qi 'Access-Control-Allow-Origin' <<<"$C1$C2$C3"; then
  if grep -Eqi 'Access-Control-Allow-Origin: \*|https://evil\.com|null' <<<"$C1$C2$C3"; then
    bad "Possible permissive CORS! Check headers below:"
    echo "$C1$C2$C3" | grep -i 'Access-Control-Allow' || true
  else
    ok "CORS present but not obviously permissive"
  fi
else
  ok "No ACAO headers observed (likely restrictive/blocked)"
fi

# 4) Cookie flags (landing page)
say "4) Cookie security flags"
SC="$(curl -s -I -L "${HTTPS}" 2>/dev/null | grep -i '^Set-Cookie' || true)"
if [[ -z "$SC" ]]; then
  warn "No cookies set on landing page (test after login flows)"
else
  echo "$SC" | while read -r line; do
    echo "  $line"
    [[ "$line" =~ [Ss]ecure ]]    || warn "↑ Missing Secure"
    [[ "$line" =~ [Hh]ttpOnly ]]  || warn "↑ Missing HttpOnly"
    [[ "$line" =~ [Ss]ame[Ss]ite ]] || warn "↑ Missing SameSite"
  done
fi

# 5) Sensitive files & backups
say "5) Sensitive files & backups"
paths=( ".env" ".git/" ".git/config" ".DS_Store" "backup.zip" "backup.tar.gz" "db.sql" "phpinfo.php" "config.php.bak" "config.old" ".htaccess.old" )
for p in "${paths[@]}"; do
  CODE="$(curl -s -o /dev/null -w '%{http_code}' "$(abs_url "$HTTPS" "$p")" 2>/dev/null || echo 000)"
  case "$CODE" in
    200) bad "$p is accessible (200)";;
    301|302|307|308) warn "$p redirects (follow manually)";;
    403) warn "$p exists but forbidden (investigate)";;
    *) info "$p → HTTP $CODE";;
  esac
done

# 6) robots/sitemap
say "6) robots.txt & sitemap.xml"
for p in robots.txt sitemap.xml; do
  URL="$(abs_url "$HTTPS" "$p")"
  CODE="$(curl -s -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null || echo 000)"
  if [[ "$CODE" == "200" ]]; then
    ok "$p found:"; curl -s "$URL" 2>/dev/null | sed -n '1,40p'
  else
    info "$p → HTTP $CODE"
  fi
done

# 7) Error handling & path traversal tease
say "7) Error handling"
R404="$(curl -s -i "$(abs_url "$HTTPS" "/this-should-404")" 2>/dev/null || true)"
if grep -qi 'exception\|trace\|stack\|Warning\|Notice\|Traceback' <<<"$R404"; then
  bad "Verbose error content detected in 404"
else
  ok "404 does not expose verbose errors"
fi
PT="$(curl -s -i "$(abs_url "$HTTPS" "/../../../../etc/passwd")" 2>/dev/null || true)"
if grep -qi 'root:x:' <<<"$PT"; then
  bad "Path traversal indication! (very unlikely via plain HTTP, but check)"
else
  info "No trivial traversal artifact in HTTP response"
fi

# 8) HTML comments
say "8) HTML comments on landing page"
curl -s "$HTTPS" 2>/dev/null | grep -n "<!--" || info "No HTML comments found in first response"

# 9) JS inventory & grep for secrets
say "9) JavaScript inventory & secret grep"
JS=$(curl -s "$HTTPS" 2>/dev/null | grep -oE 'src="[^"]+\.js[^"]*"' | cut -d'"' -f2 | sort -u)
if [[ -z "$JS" ]]; then
  info "No script tags detected on landing page"
else
  echo "$JS" | sed 's/^/  • /'
  while read -r j; do
    URL="$(abs_url "$HTTPS" "$j")"
    BODY="$(curl -s "$URL" 2>/dev/null | tr -d '\r' | sed -n '1,400p')"
    if grep -Eqi 'api[-_]?key|secret|token|Authorization|Bearer |http://|/api/' <<<"$BODY"; then
      warn "Signals in $(basename "$j") — check ${URL}"
    fi
  done <<<"$JS"
fi

# 10) Host header injection (quick)
say "10) Host header injection probe"
HRESP="$(curl -s -I -H "Host: evil.com" "$HTTPS" 2>/dev/null || true)"
if grep -qi '^Location:.*evil\.com' <<<"$HRESP"; then
  bad "Possible host header injection (Location reflects evil.com)"
else
  ok "No obvious host header reflection"
fi

# 11) TRACE method
say "11) HTTP TRACE method"
TRACE="$(curl -s -i -X TRACE "$HTTPS" 2>/dev/null || true)"
if grep -qi '^HTTP/.* 200' <<<"$TRACE"; then
  bad "TRACE enabled (potential XST)"
else
  ok "TRACE not enabled (or blocked)"
fi

hr
say "✅ Scan complete — V-lowFruit Scanner by Veron"
say "Review any ⚠️/❌ items above and pivot deeper if needed."
