const express = require('express');
const { exec } = require('child_process');
const yaml = require('js-yaml');
const https = require('https');
const app = express();

app.get('/', (req, res) => res.send('Hello, Express!'));

app.get('/exec', (req, res) => {
  const cmd = req.query.cmd;
  exec(cmd, (err, stdout) => {
    res.send(stdout);
  });
});

app.get('/eval', (req, res) => {
  const code = req.query.code;
  res.send(eval(code));
});

app.post('/yaml', express.text({ type: '*/*' }), (req, res) => {
  const doc = yaml.load(req.body);
  res.json(doc);
});

app.get('/tls', (req, res) => {
  https.get({ hostname: 'example.com', rejectUnauthorized: false }, (resp) => {
    resp.on('data', () => {});
    resp.on('end', () => res.send('done'));
  });
});

app.listen(3000);
