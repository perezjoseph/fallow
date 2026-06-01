import { getSecret } from "./secret2";
export function viaBarrel(): string | undefined {
  return getSecret();
}
