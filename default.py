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

CERTBOT_SECTION_HEADER = re.compile(r'^\[([^ ]+)\]$')
CERTBOT_CONFIG_LINE = re.compile(r'^\s*([^ ]+)\s*=\s*(.+)\s*$')


def parse_certbot_renewal(lines: List[str]) -> Dict[str, Dict[str, str]]:
    lines = (x.strip() for x in lines)
    section = 'root'
    ret = collections.defaultdict(dict)

    for line in lines:
        if not line or line.startswith('#'):
            continue

        ma = CERTBOT_SECTION_HEADER.search(line)
        if ma:
            section = ma.group(1)
            continue

        ma = CERTBOT_CONFIG_LINE.search(line)
        if not ma:
            raise Exception('invalid config file line: {}\n'.format(line))

        ret[section][ma.group(1)] = ma.group(2)

    return ret


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
        index index.html index.htm index.xml index.txt index.svg index.xml;
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

def load_certbot():
    d='/etc/letsencrypt/renewal/'
    if not os.path.exists(d):
        sys.stderr.write("letsencrypt doesn't have any certs, apparently: {} is empty\n".format(d))
        return ({}, {},)
    known_certs = {}
    webroots = {}
    for path in os.listdir(d):
        with open(d + path) as f:
            conf = parse_certbot_renewal(f.readlines())
        cert = conf['root']['cert']
        ma = re.search(r'^/etc/letsencrypt/live/([^/]*)/cert.pem$', cert)
        if not ma:
            raise Exception('invalid cert in {}: {}'.format(path, cert))
        cert = ma.group(1)

        maps = conf['[webroot_map]']

        known_certs[cert] = set(maps.keys())
        webroots.update(maps)

    return (known_certs, webroots)

known_certs, webroots = load_certbot()

configs = dict(load_config())

for server_name, config in configs.items():
    # let's not depend on ordering here; this is what certbot seems to do:
    if 1 == len(config.union_with):
        continue

    best = min(config.union_with)
    cert_to_use[server_name] = best
    for unionable in config.union_with:
        cert_to_use[unionable] = best


def ssl(cert_name: str, default: str = '', strict: bool = False):
    required_certs.add(cert_name)
    ret = """
    listen 443 ssl http2 """ + default + """;
    listen [::]:443 ssl http2 """ + default + """;
""" + r"""

    ssl on;
    ssl_certificate /etc/letsencrypt/live/{0}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{0}/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;

    ssl_stapling on;
    ssl_stapling_verify on;

    ssl_dhparam /etc/nginx/dhparam.pem;

    ssl_ciphers HIGH:+AES256:+AES128:+AESCCM:+SHA256:!SHA1:!RSA:!3DES:!CAMELLIA:!NULL:!kNULL:!aNULL:!MD5:!EXP:!PSK:!SRP:!DSS:!SEED:!SHA384:!kDH:!kECDH;

    add_header X-Clacks-Overhead "GNU Terry Pratchett";
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header X-Content-Type-Options "nosniff" always;

    """.format(cert_name)
    if strict:
        # 15,552,000 seconds = 180 days
        ret += 'add_header Strict-Transport-Security "max-age=15552000";\n'
    return ret


# unknown sites on 80 go to blog
print(r"""
server {
    listen 80 default;
    listen [::]:80 default;
    server_name junk;

    location = / {
        return 302 https://blog.goeswhere.com$request_uri;
    }
}
""")

try:
    with open('default-site.conf') as f:
        default_site = f.read().strip()
except FileNotFoundError as e:
    default_site = 'blog.goeswhere.com'

if default_site not in known_certs:
    sys.stderr.write("default site '{}' doesn't exist, so no default site is generated\n".format(default_site))
else:
    # unknown sites on 443 get the blog cert, and go to blog
    print('server {')
    print(ssl(cert_to_use.get(default_site, default_site), 'default'))
    print(r"""
        server_name junk;

        location = / {
            return 302 https://blog.goeswhere.com$request_uri;
        }
    }
    """)

# this should be in the per-thing config, but isn't because it can't be in the server{} block
print(r"""
limit_req_zone $binary_remote_addr zone=privlimit:10m rate=5r/m;

upstream websocket_pool {
ip_hash;
    server 127.0.0.1:22280;
}

map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}
""")

for server_name, config in sorted(configs.items()):
    our_cert_to_use = cert_to_use.get(server_name, server_name)

    # if the request is not ssl, redirect it: everything must be ssl
    print(r"""
server {{
    listen 80;
    listen [::]:80;
    server_name {0};
    add_header X-Clacks-Overhead "GNU Terry Pratchett";
    root {1};

    location /.well-known/ {{
        try_files $uri $uri/ =404;
    }}

    location / {{
        return 301 https://{0}$request_uri;
    }}
}}
""".format(server_name, webroots.get(server_name, '/srv/' + our_cert_to_use)))

    if our_cert_to_use not in known_certs:
        sys.stderr.write("cert for {} doesn't currently exist, so not generating config.\n"
                .format(our_cert_to_use))
        required_certs.add(our_cert_to_use)
        continue
    print("server{{\n  server_name {};\n".format(server_name))

    print(ssl(our_cert_to_use, strict=True))

    print('root {};'.format(config.root))
    print(config.location_config)

    print('}')


for cert in required_certs:
    sub_names = {cert}
    for src, dest in cert_to_use.items():
        if cert == dest:
            sub_names.add(src)
    have = known_certs.get(cert, set())
    if have == sub_names:
        continue

    sys.stderr.write("certbot certonly --webroot -w /srv/{} -d {} # {}\n"
            .format(cert, ' -d '.join(sorted(sub_names)), have))

