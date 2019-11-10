#!/bin/bash
set -ex

pip3 install -r .github/requirements.txt
.github/pages.py >gh-pages/index.html

cd gh-pages
if [ -n "$(git status --porcelain)" ]; then
	git config --global user.name 'GitHub Actions'
	git config --global user.email "$(whoami)@$(hostname --fqdn)"
	git config http.https://github.com/.extraheader "Authorization: Basic $(echo -n "dummy:${GITHUB_PERSONAL_ACCESS_TOKEN}" | base64 --wrap=0)"

	git add --all
	git commit --amend --reset-author --message 'automatic commit'
	git push --force
fi
