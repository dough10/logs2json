# logs2json

## install

Clone repo:  

```bash
git clone httpsgithub.com/dough10/logs2json
```

Configure enviroment

```bash
cd logs2json && ./setup.sh
```

Configure nginx.conf log format:  

```text
  log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for" '
                      '"$host" sn="$server_name" '
                      'rt=$request_time '
                      'ua="$upstream_addr" us="$upstream_status" '
                      'ut="$upstream_response_time" ul="$upstream_response_length" '
                      'cs=$upstream_cache_status' ;
```  

Add cron: `crontab -e` 0 0 * * * will run @ midnight  

```bash
0 0 * * * logs2json
```
