#!/bin/bash -xe
# Release packages to PyPI

if [ "$RELEASE_DIR" = "" ]; then
    echo Please run this script through the tools/release.sh wrapper script or set the environment
    echo variable RELEASE_DIR to the directory where the release should be built.
    exit 1
fi

ExitWarning() {
    exit_status="$?"
    if [ "$exit_status" != 0 ]; then
        # Don't print each command before executing it because it will disrupt
        # the desired output.
        set +x
        echo '******************************'
        echo '*                            *'
        echo '* THE RELEASE SCRIPT FAILED! *'
        echo '*                            *'
        echo '******************************'
        set -x
    fi
    exit "$exit_status"
}

trap ExitWarning EXIT

version="$1"
echo Releasing production version "$version"...
nextversion="$2"
RELEASE_BRANCH="candidate-$version"

# If RELEASE_GPG_KEY isn't set, determine the key to use.
if [ "$RELEASE_GPG_KEY" = "" ]; then
    TRUSTED_KEYS="
        BF6BCFC89E90747B9A680FD7B6029E8500F7DB16
        86379B4F0AF371B50CD9E5FF3402831161D1D280
        20F201346BF8F3F455A73F9A780CC99432A28621
        F2871B4152AE13C49519111F447BF683AA3B26C3
    "
    for key in $TRUSTED_KEYS; do
        if gpg2 --with-colons --card-status | grep -q "$key"; then
            RELEASE_GPG_KEY="$key"
            break
        fi
    done
    if [ "$RELEASE_GPG_KEY" = "" ]; then
        echo A trusted PGP key was not found on your PGP card.
        exit 1
    fi
fi

# Needed to fix problems with git signatures and pinentry
export GPG_TTY=$(tty)

# port for a local Python Package Index (used in testing)
PORT=${PORT:-1234}

# subpackages to be released (the way the script thinks about them)
SUBPKGS_NO_CERTBOT="acme certbot-apache certbot-nginx certbot-dns-cloudflare \
                    certbot-dns-digitalocean certbot-dns-dnsimple certbot-dns-dnsmadeeasy \
                    certbot-dns-gehirn certbot-dns-google certbot-dns-linode certbot-dns-luadns \
                    certbot-dns-nsone certbot-dns-ovh certbot-dns-rfc2136 certbot-dns-route53 \
                    certbot-dns-sakuracloud"
SUBPKGS="certbot $SUBPKGS_NO_CERTBOT"
# certbot_compatibility_test is not packaged because:
# - it is not meant to be used by anyone else than Certbot devs
# - it causes problems when running pytest - the latter tries to
#   run everything that matches test*, while there are no unittests
#   there

tag="v$version"
mv "dist.$version" "dist.$version.$(date +%s).bak" || true
git tag --delete "$tag" || true

tmpvenv=$(mktemp -d)
python3 -m venv "$tmpvenv"
. $tmpvenv/bin/activate
# update packaging tools to their pinned versions
tools/pip_install.py virtualenv

root_without_le="$version.$$"
root="$RELEASE_DIR/le.$root_without_le"

echo "Cloning into fresh copy at $root"  # clean repo = no artifacts
git clone . $root
git rev-parse HEAD
cd $root
if [ "$RELEASE_BRANCH" != "candidate-$version" ] ; then
    git branch -f "$RELEASE_BRANCH"
fi
git checkout "$RELEASE_BRANCH"

# Update changelog
sed -i "s/master/$(date +'%Y-%m-%d')/" certbot/CHANGELOG.md
git add certbot/CHANGELOG.md
git commit -m "Update changelog for $version release"

for pkg_dir in $SUBPKGS certbot-compatibility-test
do
  sed -i 's/\.dev0//' "$pkg_dir/setup.py"
  git add "$pkg_dir/setup.py"
done

SetVersion() {
    ver="$1"
    # bumping Certbot's version number is done differently
    for pkg_dir in $SUBPKGS_NO_CERTBOT certbot-compatibility-test
    do
      setup_file="$pkg_dir/setup.py"
      if [ $(grep -c '^version' "$setup_file") != 1 ]; then
        echo "Unexpected count of version variables in $setup_file"
        exit 1
      fi
      sed -i "s/^version.*/version = '$ver'/" $pkg_dir/setup.py
    done
    init_file="certbot/certbot/__init__.py"
    if [ $(grep -c '^__version' "$init_file") != 1 ]; then
      echo "Unexpected count of __version variables in $init_file"
      exit 1
    fi
    sed -i "s/^__version.*/__version__ = '$ver'/" "$init_file"

    git add $SUBPKGS certbot-compatibility-test
}

SetVersion "$version"

# Unset CERTBOT_OLDEST to prevent wheels from being built improperly due to
# conditionals like the one found in certbot-dns-dnsimple's setup.py file.
unset CERTBOT_OLDEST
echo "Preparing sdists and wheels"
for pkg_dir in $SUBPKGS
do
  cd $pkg_dir

  python setup.py clean
  rm -rf build dist
  python setup.py sdist
  python setup.py bdist_wheel

  echo "Signing ($pkg_dir)"
  for x in dist/*.tar.gz dist/*.whl
  do
      gpg2 -u "$RELEASE_GPG_KEY" --detach-sign --armor --sign --digest-algo sha256 $x
  done

  cd -
done


mkdir "dist.$version"
for pkg_dir in $SUBPKGS
do
  mv $pkg_dir/dist/* "dist.$version"
done

echo "Testing packages"
cd "dist.$version"
# cd .. is NOT done on purpose: we make sure that all subpackages are
# installed from local archives rather than current directory (repo root)
VIRTUALENV_NO_DOWNLOAD=1 virtualenv ../venv
. ../venv/bin/activate
pip install -U setuptools
pip install -U pip

# This creates a string like "acme==a.b.c certbot==a.b.c ..." which can be used
# with pip to ensure the correct versions of our packages installed.
subpkgs_with_version=""
for pkg in $SUBPKGS; do
    subpkgs_with_version="$subpkgs_with_version $pkg==$version"
done

# Now, use our local archives. Disable cache so we get the correct packages even if
# we (or our dependencies) have conditional dependencies implemented with if
# statements in setup.py and we have cached wheels lying around that would cause
# those ifs to not be evaluated.
python ../tools/pip_install.py \
  --no-cache-dir \
  --find-links . \
  $subpkgs_with_version
cd ~-

# get a snapshot of the CLI help for the docs
# We set CERTBOT_DOCS to use dummy values in example user-agent string.
CERTBOT_DOCS=1 certbot --help all > certbot/docs/cli-help.txt
jws --help > acme/docs/jws-help.txt

deactivate


git add certbot/docs/cli-help.txt
while ! git commit --gpg-sign="$RELEASE_GPG_KEY" -m "Release $version"; do
    echo "Unable to sign the release commit using git."
    echo "You may have to configure git to use gpg2 by running:"
    echo 'git config --global gpg.program $(command -v gpg2)'
    read -p "Press enter to try signing again."
done
git tag --local-user "$RELEASE_GPG_KEY" --sign --message "Release $version" "$tag"

towncrier build
git add certbot/CHANGELOG.md
git commit -m "Add contents to certbot/CHANGELOG.md for next version"

if [ "$RELEASE_BRANCH" = candidate-"$version" ] ; then
    SetVersion "$nextversion".dev0
    git commit -m "Bump version to $nextversion"
fi
