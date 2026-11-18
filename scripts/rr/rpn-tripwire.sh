#!/usr/bin/env bash
# Fails when upstream changes something the fork relies on to keep RPN / billing hidden in the fdroid flavor.
# On failure, follow docs/fork/UPSTREAM_SYNC.md §6 (regenerate overlay or gate new entry points).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
fail=0
err() { echo "TRIPWIRE: $*"; fail=1; }

# 1. Our bottom-nav overlay must be upstream's menu minus the rethinkPlus item.
up=app/src/main/res/menu/bottom_nav_menu.xml; ov=app/fork/res/menu/bottom_nav_menu.xml
if [ -f "$up" ] && [ -f "$ov" ]; then
  python3 -I - "$up" "$ov" <<'PY2' || err "$ov is out of date with $up (regenerate: upstream menu minus @+id/rethinkPlus)"
import re, sys
def norm(s):
    s = re.sub(r'<!--.*?-->', '', s, flags=re.S)
    return re.sub(r'\s+', '', s)
up = open(sys.argv[1], encoding='utf-8').read()
up = re.sub(r'<item\b[^>]*@\+id/rethinkPlus"[^>]*?(?:/>|>.*?</item>)', '', up, flags=re.S)
sys.exit(0 if norm(up) == norm(open(sys.argv[2], encoding='utf-8').read()) else 1)
PY2
else
  err "missing $up or $ov"
fi

# 2. The fdroid flavor must keep its source-level billing stubs and must not pull in Play Billing / Stripe.
for f in app/src/fdroid/java/com/android/billingclient/api/BillingClient.kt \
         app/src/fdroid/java/com/celzero/bravedns/iab/InAppBillingHandler.kt; do
  [ -f "$f" ] || err "fdroid billing stub removed: $f (upstream may be enabling RPN in fdroid)"
done
grep -v '^[[:space:]]*//' app/build.gradle.kts | grep -Eq '"?fdroidImplementation"?\(.*(billing|stripe)' \
  && err "app/build.gradle.kts adds a billing/stripe dependency to the fdroid flavor"

# 3. The fork's RPN switch must be present.
grep -q 'RR_RPN_ENABLED' app/fork/rethinkreloaded.gradle || err "RR_RPN_ENABLED missing from fork gradle layer"

[ $fail -eq 0 ] && echo "rpn tripwire OK"
exit $fail
