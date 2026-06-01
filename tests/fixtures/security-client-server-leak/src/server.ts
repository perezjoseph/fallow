export function getData(): string | undefined {
  return process.env.DATABASE_URL;
}
