// Mock OpenAI-compatible upstream for local testing.
// Serves /models and any POST /v1/...  with a fake completion + usage.
// Test drivers control the simulated cost with headers:
//   X-Tokens: <int>            -> usage.total_tokens returned (default 100)
//   X-Force-Status: <code>     -> always respond with this HTTP status
const express = require('express');
const app = express();
app.use(express.json({ limit: '1mb' }));

app.get('/v1/models', (_req, res) => {
  res.json({ object: 'list', data: [{ id: 'mock-model', object: 'model' }] });
});

app.post('/v1/*', (req, res) => {
  const force = parseInt(req.headers['x-force-status'] || '0', 10);
  if (force && force !== 200) {
    const title = force === 401 ? 'Invalid Authentication' : force === 429 ? 'Rate limit reached for requests' : 'Error';
    return res.status(force).json({ error: { message: title, type: 'invalid_request_error' } });
  }
  const tokens = parseInt(req.headers['x-tokens'] || '100', 10);
  res.json({
    id: 'chatcmpl-mock-' + Date.now(),
    object: 'chat.completion',
    model: 'mock-model',
    choices: [{ index: 0, message: { role: 'assistant', content: 'hello from mock' }, finish_reason: 'stop' }],
    usage: { prompt_tokens: Math.ceil(tokens / 2), completion_tokens: Math.floor(tokens / 2), total_tokens: tokens },
  });
});

app.use((_req, res) => res.status(404).json({ error: { message: 'not found', type: 'not_found' } }));

const port = parseInt(process.env.PORT || '4010', 10);
app.listen(port, () => console.log('[mock-upstream] listening on :' + port));
