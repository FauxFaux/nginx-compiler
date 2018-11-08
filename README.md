# nginx-compiler

This tool generates `nginx` config to serve `/srv` like my old lighttpd setup,
which was based on my old Apache setup, which was based on...

Rough rules:

 1. the compiler owns the `/etc/nginx/sites-available/default`
 2. `/srv/sub.example.com/foo.txt` should be available at `http[s]://sub.example.com/foo.txt`
 3. the certs are managed by `certbot`
 4. some domains have an extra config fragment, in `/srv/.sub.example.com.nginx`
 5. changes are infrequent enough that manually doing some bits is fine

As you can tell, this is a custom tool for my site only, but should be easy to fork.
Be aware that there's *plenty* more hard-coded assumptions.
