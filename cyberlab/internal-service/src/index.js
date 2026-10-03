const http = require('http');

const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');

  if (req.url === '/health') {
    res.writeHead(200);
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }

  if (req.url === '/internal/demo-secret') {
    res.writeHead(200);
    res.end(JSON.stringify({
      secret: 'demo_internal_secret_123',
      message: 'SSRF target reached - this is a harmless demo endpoint',
      warning: 'This endpoint should not be accessible from external requests',
    }));
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(8080, () => {
  console.log('[InternalService] Running on port 8080');
});
