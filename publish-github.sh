#!/bin/sh
# linklens GitHub 镜像发布（token 从钥匙串读，不回显）
set -e
cd "$(dirname "$0")"
GIT="${GIT:-$(command -v git || echo /usr/bin/git)}"

GH_TOKEN=$(security find-generic-password -s GH_TOKEN -a tomlen045 -w 2>/dev/null)
[ -n "$GH_TOKEN" ] || { echo "no GH_TOKEN in keychain"; exit 1; }

echo "-> create github repo tomlen045/linklens ..."
HTTP=$(curl -s -o /tmp/gh_linklens.json -w '%{http_code}' \
  -H "Authorization: token $GH_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/user/repos \
  -d '{"name":"linklens","description":"linklens - broken-link archaeology and symlink risk lens in one file: dead (fresh/stale), loop, escape, kernelcap (MAXSYMLINKS=32), temp/scope component-level, baseline retarget watch. 328 selftest invariants, zero dependencies.","has_wiki":false,"private":false}')
if [ "$HTTP" = "201" ]; then echo "  created"
elif [ "$HTTP" = "422" ]; then echo "  exists, skip"
else echo "  HTTP $HTTP: $(head -c 200 /tmp/gh_linklens.json)"; exit 1; fi

if ! "$GIT" remote get-url github >/dev/null 2>&1; then
  "$GIT" remote add github git@github.com:tomlen045/linklens.git
fi
# ensure IdentityFile-bearing alias is used (per memory: never write git@ssh.github.com: directly)
"$GIT" remote set-url github git@github.com:tomlen045/linklens.git
echo "-> push main ..."
"$GIT" push -u github master:main && echo "  pushed"

sleep 3
CODE_API=$(curl -s -o /tmp/gh_ll_read.json -w '%{http_code}' \
  -H "Authorization: token $GH_TOKEN" https://api.github.com/repos/tomlen045/linklens)
CODE_RAW=$(curl -s -o /dev/null -w '%{http_code}' https://raw.githubusercontent.com/tomlen045/linklens/main/README.md)
CODE_CDN=$(curl -s -o /dev/null -w '%{http_code}' https://gcore.jsdelivr.net/gh/tomlen045/linklens@main/README.md)
echo "  API=$CODE_API | raw README=$CODE_RAW | gcore CDN=$CODE_CDN"
if [ "$CODE_API" = "200" ] && [ "$CODE_RAW" = "200" ]; then
  echo "OK https://github.com/tomlen045/linklens"
else
  echo "VERIFY FAILED"
  exit 2
fi
