from flask import Flask, request
import subprocess, yaml, pickle, requests

app = Flask(__name__)

@app.route('/')
def index():
    return 'Hello, Flask!'

@app.route('/exec')
def exec_cmd():
    cmd = request.args.get('cmd')
    if cmd:
        subprocess.call(cmd, shell=True)
    return 'executed'

@app.route('/eval')
def do_eval():
    code = request.args.get('code')
    return str(eval(code))

@app.route('/yaml', methods=['POST'])
def parse_yaml():
    return str(yaml.load(request.data))

@app.route('/pickle', methods=['POST'])
def parse_pickle():
    return str(pickle.loads(request.data))

@app.route('/tls')
def tls():
    requests.get('https://example.com', verify=False)
    return 'insecure'

if __name__ == '__main__':
    app.run()
