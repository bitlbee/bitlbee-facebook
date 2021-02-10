#!/bin/bash

set -e

FULLVERS="$(date +%Y%m%d)~$(git rev-parse --short=7 HEAD)~${GITHUB_RUN_NUMBER}"
FULLDATE=$(date -R)
REPONAME=$(basename "${GITHUB_REPOSITORY}")

git reset -q --hard
git clean -dfqx

mkdir debian

sed -ri \
    -e "18 s/^(\s+).*(,)\$/\1\[${FULLVERS}\]\2/" \
    -e "s|^PKG_CHECK_MODULES\(\[BITLBEE\].*|plugindir=/usr/lib/bitlbee|" \
    configure.ac

sed -ri \
    -e "s/bitlbee-dev \([^\(\)]+\),?\s*//" \
    -e "s/(bitlbee[^ ]*) \(>= 3.4\)/\1 (>= 3.5)/g" \
    debian/control
cp debian/control ~/debian/control

cat <<EOF > ~/debian/changelog
${REPONAME} (${FULLVERS}) UNRELEASED; urgency=medium

  * Updated to ${FULLVERS}.

 -- Travis CI <travis@travis-ci.org>  ${FULLDATE}
EOF

mkdir -p ~/.config/osc/
cat <<EOF > ~/.config/osc/oscrc
[general]
apiurl = https://api.opensuse.org
[https://api.opensuse.org]
user = ${OBSUSER}
pass = ${OBSPASS}
credentials_mgr_class=osc.credentials.PlaintextConfigFileCredentialsManager
EOF

mkdir -p m4
cp /usr/local/include/bitlbee/*.h facebook
osc checkout "home:jgeboski" "${REPONAME}" -o /tmp/obs

(
    cd /tmp/obs
    rm -f *.{dsc,tar.gz}
    dpkg-source -c"~/debian/control" -l"~/debian/changelog" -I -b "${TRAVIS_BUILD_DIR}"

    osc addremove -r
    osc commit -m "Updated to ${FULLVERS}"
)
