#!/bin/bash

set -e
set -x

if [[ "$(uname -s)" == 'Darwin' ]]; then
    if which pyenv > /dev/null; then
        eval "$(pyenv init -)"
    fi
    pyenv activate pyftpdlib
fi

pip install flake8 pyopenssl mock
python setup.py install
python pyftpdlib/test/runner.py
flake8
