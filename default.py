#!/usr/bin/env python3
import collections
import glob
import os
import re
import sys

from typing import Dict, List, Set, Tuple, Iterable

Config = collections.namedtuple('Config', ['root', 'union_with', 'location_config'])

servers = list(sorted(os.path.basename(server_path)
                      for server_path in sorted(glob.glob('/srv/*.*'))
                      if os.path.isdir(server_path)))  # type: List[str]

required_certs = set()  # type: Set[str]
cert_to_use = dict()  # type: Dict[str, str]

CONFIG_LINE = re.compile('^([a-z_]{4,}): (.*)')


def parse_config(server_name: str, contents: str) -> Config:
    """
    >>> parse_config("foo", "root: /ponies")
    Config(root='/ponies', union_with=set(), location_config='')
    >>> parse_config("foo", "bar")
    Config(root='/srv/foo', union_with=set(), location_config='bar')
    >>> parse_config("foo", "union_with: baz bux\\nbar")
    Config(root='/srv/foo', union_with={'bux', 'baz'}, location_config='bar')
    """
    lines = contents.splitlines()
    settings = {}  # type: Dict[str, str]
    location_config = r"""
    location / {
        index index.html index.htm index.xml index.txt index.svg;
        try_files $uri $uri/ =404;
    }
"""

    for index, line in enumerate(lines):
        ma = CONFIG_LINE.match(line)
        if ma:
            settings[ma.group(1)] = ma.group(2)
        else:
            location_config = '\n'.join(lines[index:])
            break

    ret = Config(
        settings.pop('root', '/srv/' + server_name),
        set(x for x in ([server_name] + settings.pop('union_with', '').split(' ')) if x),
        location_config
    )
    assert 0 == len(settings)
    return ret


def load_config() -> Iterable[Tuple[str, Config]]:
    for server_name in servers:
        try:
            with open("/srv/.{}.nginx".format(server_name)) as f:
                contents = f.read()
        except FileNotFoundError as e:
            contents = ''

        yield (server_name, parse_config(server_name, contents))


configs = dict(load_config())

for server_name, config in configs.items():
    # let's not depend on ordering here; this is what certbot seems to do:
    if 1 == len(config.union_with):
        continue

    best = min(config.union_with)
    cert_to_use[server_name] = best
    for unionable in config.union_with:
        cert_to_use[unionable] = best


def ssl(cert_name: str, default: str = ''):
    required_certs.add(cert_name)
    return """
    listen 443 ssl http2 """ + default + """;
    listen [::]:443 ssl http2 """ + default + """;
""" + r"""

    ssl on;
    ssl_certificate /etc/letsencrypt/live/{0}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{0}/privkey.pem;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;

    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/nginx/ca.pem;

    ssl_dhparam /etc/nginx/dhparam.pem;

    ssl_ciphers EECDH+ECDSA+AESGCM:HIGH:+AES256:+DH:+RSA:+SHA:!3DES:!CAMELLIA:!NULL:!aNULL:!LOW:!MD5:!EXP:!PSK:!SRP:!DSS:!SEED:!SHA384;

    add_header X-Clacks-Overhead "GNU Terry Pratchett";
""".format(cert_name)


# add_header Strict-Transport-Security "max-age=15552000";
# 15,552,000 seconds = 180 days

# unknown sites on 80 go to blog
print(r"""
server {
    listen 80 default;
    listen [::]:80 default;
    server_name junk;

    location = / {
        return 302 https://blog.goeswhere.com/;
    }
}
""")

# unknown sites on 443 get the blog cert, and go to blog
print('server {')
print(ssl(cert_to_use['blog.goeswhere.com'], 'default'))
print(r"""
    server_name junk;

    location = / {
        return 302 https://blog.goeswhere.com/;
    }
}
""")

# this should be in the per-thing config, but isn't because it can't be in the server{} block
print(r"""
upstream websocket_pool {
ip_hash;
    server 127.0.0.1:22280;
}

map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}
""")

for server_name, config in configs.items():
    our_cert_to_use = cert_to_use.get(server_name, server_name)

    # if the request is not ssl, redirect it: everything must be ssl
    print(r"""
server {{
    listen 80;
    listen [::]:80;
    server_name {0};
    add_header X-Clacks-Overhead "GNU Terry Pratchett";
    root /srv/{1};

    location /.well-known/ {{
        try_files $uri $uri/ =404;
    }}

    location / {{
        return 301 https://{0}$request_uri;
    }}
}}
""".format(server_name, our_cert_to_use))

    print("server{{\n  server_name {};\n".format(server_name))

    print(ssl(our_cert_to_use))

    print('root {};'.format(config.root))
    print(config.location_config)

    print('}')


for cert in required_certs:
    if os.path.exists('/etc/letsencrypt/renewal/{}.conf'.format(cert)):
        continue
    sub_names = {cert}
    for src, dest in cert_to_use.items():
        if cert == dest:
            sub_names.add(src)
    sys.stderr.write("certbot certonly --webroot -w /srv/{} -d {}\n".format(cert, ' -d '.join(sorted(sub_names))))
