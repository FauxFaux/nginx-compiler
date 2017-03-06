#!/bin/zsh
set -eu
set -o pipefail

./default.py | sudo tee /etc/nginx/sites-enabled/default > /dev/null
sudo service nginx reload
