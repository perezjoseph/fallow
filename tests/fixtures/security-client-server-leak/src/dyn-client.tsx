"use client";
export function loadModule(name: string) {
  return import(`./mods/${name}`);
}
