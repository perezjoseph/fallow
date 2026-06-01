// fallow-ignore-file security-client-server-leak
"use client";
import { getData } from "./server";
export const Suppressed = getData();
