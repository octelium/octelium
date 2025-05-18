const isDevVal = import.meta.env.MODE === "development";

export function isDev(): boolean {
  return isDevVal;
}
