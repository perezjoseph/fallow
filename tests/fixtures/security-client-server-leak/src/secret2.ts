export function getSecret(): string | undefined {
  return process.env.SESSION_SECRET;
}
