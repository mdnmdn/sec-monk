import json, sys
from secmonk.collectors import base as b
keys = ["token","api_key","apiKey","API-KEY","author","authors","authorization","auth","authority","AUTHORS_FILE","oauth",
        "authored","authorsx","auth_token","password","passwd","pwd","private_key","privatekey","credential","secret_name",
        "name","Auth","AuThOrS","authorſ","authorS","authOrs1","user","x-auth-or","key","monkey","ssh_option","host",
        "identity","tls_key","tls_key_passphrase","known_hosts","cert_file","socket_path","ssh_config","url","endpoint",
        "socket","passphrase","pass","apikey\n","key\n","cfg_file\n","label","kubeconfig","context","port"]
urls = ["https://user:pw@example.com:8443/path?q=1#frag","http://user@host/x","unix:///var/run/docker.sock",
        "git@github.com:org/repo.git","","plain","https://h/p?","ssh://a:b@c:22","https://a@b@c/d","https://x.y/path.",
        "tcp://[::1]:2375/","s3://AKIA:secret@bucket/k?X-Amz-Signature=abc","://nohost","HTTP://U:P@H/","https://é:ü@hé.com/ö?x"]
cmds = [["--password","x","--token=abc","KEY=v","API_KEY=1","https://u:p@h/x","-p","--auth","s","plain"],
        ["sh","-c","curl https://u:p@h/x"],["--authors=me","--author","x"],["-x=1","---secret=2","a=b=c","=x"],
        ["--Password","hide","--next"],["mysql","-uroot","--password"],["é=1","naïve_token=2"],["--token"],[]]
strs = ["sshpass -p hunter2 ssh host","ProxyCommand=sshpass -e -f x -p secret ssh -W %h:%p jump",
        "ProxyCommand ssh -W %h:%p user@jump","--token=abc  https://u:p@h/x"," lead","sshpass  -p\tpw ssh"]
texts = ["error: GET https://user:pw@api.example.com/v1?token=abc failed","no urls here",
         "two http://a:b@x/1 and ftp://c:d@y/2?z","quote 'https://u:p@h/x' end","<https://u:p@h/x>",
         "x\x1chttps://u:p@h/y\x1fz","weird schemeé://u:p@h/","9http://u:p@h/","a.b+c-d://u:p@h/p#f",
         "https://u:p@h/p\u00a0next","tab\thttps://u:p@h/p\nnewline",None,""]
out = {"looks_secret": [[k, b.looks_secret(k)] for k in keys],
       "strip_url_secrets": [[u, b.strip_url_secrets(u), b.strip_url_secrets(u, keep_user=True)] for u in urls],
       "redact_command_list": [[c, b.redact_command(c)] for c in cmds],
       "redact_command_str": [[c, b.redact_command(c)] for c in strs],
       "scrub_text": [[t, b.scrub_text(t)] for t in texts]}
opts = []
for k in keys:
    for v in ["https://u:p@h/x?q", "plain", "sshpass -p pw ssh h", 5, None, True, ["a","https://u:p@h/y"], "C:\\path\\x"]:
        opts.append([k, v, b.redact_option(k, v)])
out["redact_option"] = opts
out["redact_labels"] = [[d, b.redact_labels(d)] for d in [
    {"maintainer":"me","org.opencontainers.image.source":"https://u:p@github.com/x?y","API_TOKEN":"abc","n":3,"auth":None,"authors":"x"},
    {}, None]]
json.dump(out, sys.stdout, ensure_ascii=False, indent=1)
