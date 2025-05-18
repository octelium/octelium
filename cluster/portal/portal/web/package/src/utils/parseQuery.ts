type QueryValue = string | number | boolean | QueryObject | QueryValue[];
type QueryObject = { [key: string]: QueryValue };

export default function <T extends QueryObject>(query: string): T {
  const params = new URLSearchParams(query);
  const result: QueryObject = {};

  for (const [key, value] of params.entries()) {
    setQueryValue(result, key, parseSingleValue(value));
  }

  return result as T;
}

function parseSingleValue(value: string): QueryValue {
  if (value === "true") return true;
  if (value === "false") return false;

  if (!isNaN(Number(value)) && value.trim() !== "") return Number(value);

  return value;
}

function setQueryValue(
  obj: QueryObject,
  path: string,
  value: QueryValue
): void {
  const [baseKey, ...rest] = path.split(/[\[\].]/).filter(Boolean);

  if (!baseKey) return;

  if (rest.length === 0) {
    if (path.endsWith("[]")) {
      const cleanKey = path.slice(0, -2);
      if (!obj[cleanKey]) {
        obj[cleanKey] = [];
      }
      (obj[cleanKey] as QueryValue[]).push(value);
    } else {
      obj[path] = value;
    }
  } else {
    if (!obj[baseKey]) {
      obj[baseKey] = {};
    }

    const nestedObj = obj[baseKey] as QueryObject;
    const nestedPath = rest.join(".");

    setQueryValue(nestedObj, nestedPath, value);
  }
}
