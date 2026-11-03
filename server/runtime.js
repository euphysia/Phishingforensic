/**
 * Runtime detection — true when running inside a Netlify Function
 * (AWS Lambda under the hood) rather than the long-lived local server.
 * Serverless invocations are capped at 60 s and cannot keep sockets open,
 * so some features (SMTP listener, SSE, long API polling) are scaled back.
 */
export const IS_SERVERLESS = Boolean(
  process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NETLIFY_FUNCTION || process.env.LAMBDA_TASK_ROOT
);
