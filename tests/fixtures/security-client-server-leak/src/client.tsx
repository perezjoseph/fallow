"use client";
import { getData } from "./server";
export function ClientView() {
  return getData();
}
