export const tags = ["laravel", "all"];

export default async function run(target, fetchWithRetry) {
  try {
    const res = await fetchWithRetry(`${target}/storage/logs/laravel.log`);

    const text = res.text.toLowerCase();

    if (text.includes("exception") || text.includes("stack trace")) {
      return {
        name: "laravel log exposure",
        status: "VULNERABLE",
        severity: "HIGH",
        fix: "Deny public access to the '/storage' directory in your web server configuration or move the storage folder outside of the web root."
      };
    }

    return {
      name: "laravel log exposure",
      status: "SAFE",
      severity: "NONE"
    };

  } catch (e) {
    return {
      name: "laravel log exposure",
      status: "ERROR",
      severity: "LOW"
    };
  }
}