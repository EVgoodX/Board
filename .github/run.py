# 暗号化された処理（.github/s.bin）をパスワードで復号して実行する。暗号の方式は index.html と同じ
import os, sys, json, hashlib, hmac, base64, subprocess
SALT = bytes.fromhex('eb554b683d8e5733e899b28199e11073')
K = hashlib.pbkdf2_hmac('sha256', os.environ['BOARD_PW'].encode('utf-8'), SALT, 600000, 64)

def ssl(args, iv, data):
    return subprocess.run(['openssl', 'enc'] + args + ['-aes-256-cbc', '-K', K[:32].hex(), '-iv', iv.hex()], input=data, capture_output=True, check=True).stdout

def unseal(path):
    box = json.load(open(path, encoding='utf-8'))
    iv, ct, mac = (base64.b64decode(box[x]) for x in ('iv', 'ct', 'mac'))
    if not hmac.compare_digest(hmac.new(K[32:], iv + ct, hashlib.sha256).digest(), mac):
        sys.exit('wrong key')
    return ssl(['-d'], iv, ct).decode('utf-8')

def seal(text, path):
    data = text.encode('utf-8'); iv = os.urandom(16); ct = ssl([], iv, data)
    assert ssl(['-d'], iv, ct) == data
    mac = hmac.new(K[32:], iv + ct, hashlib.sha256).digest()
    b = lambda x: base64.b64encode(x).decode()
    open(path, 'w', encoding='utf-8').write(json.dumps({'iv': b(iv), 'ct': b(ct), 'mac': b(mac)}, separators=(',', ':')))

exec(compile(unseal('.github/s.bin'), 'job', 'exec'), {'unseal': unseal, 'seal': seal, '__name__': '__main__'})
