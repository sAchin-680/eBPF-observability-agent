// Sample HTTPS service used to verify tracing of unmodified applications.
// Contains no instrumentation.

const fs = require('fs');
const https = require('https');
const express = require('express');

const app = express();
app.use(express.json());

const users = [
  { id: 1, name: 'ada' },
  { id: 2, name: 'grace' },
  { id: 3, name: 'katherine' },
];

app.get('/health', (req, res) => res.send('ok'));

app.get('/users', (req, res) => res.json(users));

app.post('/users', (req, res) => res.status(201).json({ id: users.length + 1, name: 'new' }));

app.get('/users/:id', (req, res) => {
  if (req.params.id === '999') {
    return res.status(404).json({ error: 'no such user' });
  }
  res.json(users[0]);
});

app.get('/slow', (req, res) => setTimeout(() => res.send('slow'), 150));

app.get('/error', (req, res) => res.status(500).json({ error: 'deliberate failure' }));

const cert = process.env.CERT || '../certs/cert.pem';
const key = process.env.KEY || '../certs/key.pem';
const port = Number(process.env.PORT || 8445);

https
  .createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, app)
  .listen(port, () => console.log(`node-express listening on ${port}`));
