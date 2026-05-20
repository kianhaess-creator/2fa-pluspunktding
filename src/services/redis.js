const Redis = require('ioredis');
const config = require('../config');

const client = new Redis(config.redis.url, {
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
});

client.on('error', (err) => {
  console.error('[Redis] Connection error:', err.message);
});

module.exports = client;
