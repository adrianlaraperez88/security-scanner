export const tags = ["all"];

export default async function run(target, fetchWithRetry) {
  try {
    const res = await fetchWithRetry(`${target}/.git/HEAD`);

    if (res.text.includes('ref:')) {
      return {
        name: ".git exposure",
        status: "VULNERABLE",
        severity: "HIGH",
        fix: "Remove the '.git' folder from the production web server or deny all access strictly in your web server configuration."
      };
    }

    return {
      name: ".git exposure",
      status: "SAFE",
      severity: "NONE"
    };

  } catch (e) {
    return {
      name: ".git exposure",
      status: "ERROR",
      severity: "LOW",
      reason: e.message
    };
  }
}