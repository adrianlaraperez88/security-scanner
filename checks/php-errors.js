export const tags = ["php", "all"];

export default async function run(target, fetchWithRetry) {
  try {
    const res = await fetchWithRetry(target);

    const html = res.text.toLowerCase();

    const errors = [
      "fatal error",
      "warning:",
      "parse error",
      "undefined index",
      "stack trace"
    ];

    const hits = errors.filter(e => html.includes(e));

    const status = hits.length ? "SUSPICIOUS" : "SAFE";
    if (status === "SAFE") return { name: "php error exposure", status: "SAFE", severity: "NONE" };

    return {
      name: "php error exposure",
      status: "SUSPICIOUS",
      severity: hits.length > 2 ? "MEDIUM" : "LOW",
      fix: "Disable error display in production by setting 'display_errors = Off' and 'log_errors = On' in your php.ini or application config."
    };

  } catch (e) {
    return {
      name: "php error exposure",
      status: "ERROR",
      severity: "LOW"
    };
  }
}