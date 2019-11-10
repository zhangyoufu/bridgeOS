#!/bin/bash
set -ex

pip3 install -r .github/requirements.txt
.github/release.py
