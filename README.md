# nginx_http_secdownload
For those who want to migrate from lighttpd mod_secdownload to nginx
http://redmine.lighttpd.net/projects/1/wiki/Docs_ModSecDownload

##Lighttpd config:
```
secdownload.secret        = secret
secdownload.document-root = /var/www/html/secure
secdownload.uri-prefix    = /dl/
secdownload.timeout       = 3600
```

##nginx config:
```
location /dl/ {
    secdownload.secret "secret";
    secdownload.uri-prefix "/dl/";
    secdownload.timeout 3600;

    rewrite ^ /secure/$secdownload_uri;
}

location /secure {
    root /var/www/html;
    internal;
}
```
