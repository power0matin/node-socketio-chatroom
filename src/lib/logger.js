'use strict';

const SECRET_KEYS = /pass(word)?|hash|token|secret|key/i;

function redact(value) {
  if (!value || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(redact);
  const out = {};
  for (const [key, item] of Object.entries(value)) out[key] = SECRET_KEYS.test(key) ? '[REDACTED]' : (item && typeof item === 'object' ? redact(item) : item);
  return out;
}

function log(level, component, message, context = undefined) {
  const record = {
    ts: new Date().toISOString(),
    level,
    component,
    message,
  };
  if (context && Object.keys(context).length) record.context = redact(context);
  const line = JSON.stringify(record);
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

module.exports = {
  debug: (component, message, context) => { if (process.env.LOG_LEVEL === 'debug') log('debug', component, message, context); },
  info: (component, message, context) => log('info', component, message, context),
  warn: (component, message, context) => log('warn', component, message, context),
  error: (component, message, context) => log('error', component, message, context),
  redact,
};
