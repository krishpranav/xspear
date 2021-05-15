# xspear
xspear is a xss vulnerability scanner made in ruby

[![forthebadge](https://forthebadge.com/images/badges/made-with-ruby.svg)](https://forthebadge.com)

# Installation
```
git clone https://github.com/krishpranav/xspear
cd xspear
bundle install
bundle
```

# Usage
```
Usage: xspear -u [target] -[options] [value]
[ e.g ]
$ xspear -u 'https://www.hahwul.com/?q=123' --cookie='role=admin' -v 1 -a 
$ xspear -u 'http://testphp.vulnweb.com/listproducts.php?cat=123' -v 2
$ xspear -u 'http://testphp.vulnweb.com/listproducts.php?cat=123' -v 0 -o json

[ Options ]
    -u, --url=target_URL             [required] Target Url
    -d, --data=POST Body             [optional] POST Method Body data
    -a, --test-all-params            [optional] test to all params(include not reflected)
        --no-xss                     [optional] no testing xss, only parameters analysis
        --headers=HEADERS            [optional] Add HTTP Headers
        --cookie=COOKIE              [optional] Add Cookie
        --custom-payload=FILENAME    [optional] Load custom payload json file
        --raw=FILENAME               [optional] Load raw file(e.g raw_sample.txt)
    -p, --param=PARAM                [optional] Test paramters
    -b, --BLIND=URL                  [optional] Add vector of Blind XSS
                                      + with XSS Hunter, ezXSS, HBXSS, etc...
                                      + e.g : -b https://hahwul.xss.ht
    -t, --threads=NUMBER             [optional] thread , default: 10
    -o, --output=FORMAT              [optional] Output format (cli , json)
    -c, --config=FILENAME            [optional] Using config.json
    -v, --verbose=0~3                [optional] Show log depth
                                      + v=0 : quite mode(only result)
                                      + v=1 : show scanning status(default)
                                      + v=2 : show scanning logs
                                      + v=3 : show detail log(req/res)
    -h, --help                       Prints this help
        --version                    Show XSpear version
        --update                     Show how to update

```

# quite mode
```
$ xspear -u "http://testphp.vulnweb.com/listproducts.php?cat=123" -v 0
```

# show progress bar
```
$ xspear -u "http://testphp.vulnweb.com/listproducts.php?cat=123" -v 1
[*] analysis request..
[*] used test-reflected-params mode(default)
[*] creating a test query [for reflected 2 param + blind XSS ]
[*] test query generation is complete. [249 query]
[*] starting XSS Scanning. [10 threads]

[#######################################] [249/249] [100.00%] [01:05] [00:00] [  3.83/s]
...
```

# show scanning logs
```
$ xspear -u "http://testphp.vulnweb.com/listproducts.php?cat=123" -v 2
[*] analysis request..
[I] [22:42:41] [200/OK] [param: cat][Found SQL Error Pattern]
[-] [22:42:41] [200/OK] 'STATIC' not reflected
[-] [22:42:41] [200/OK] 'cat' not reflected <script>alert(45)</script>
[I] [22:42:41] [200/OK] reflected rEfe6[param: cat][reflected parameter]
[*] used test-reflected-params mode(default)
[*] creating a test query [for reflected 2 param + blind XSS ]
[*] test query generation is complete. [249 query]
[*] starting XSS Scanning. [10 threads]
[I] [22:42:43] [200/OK] reflected onhwul=64[param: cat][reflected EHon{any} pattern]
[-] [22:42:54] [200/OK] 'cat' not reflected <img/src onerror=alert(45)>
[-] [22:42:54] [200/OK] 'cat' not reflected <svg/onload=alert(45)>
[H] [22:42:54] [200/OK] reflected <script>alert(45)</script>[param: cat][reflected XSS Code]
[V] [22:42:59] [200/OK] found alert/prompt/confirm (45) in selenium!! '"><svg/onload=alert(45)>[param: cat][triggered <svg/onload=alert(45)>]
...
```
