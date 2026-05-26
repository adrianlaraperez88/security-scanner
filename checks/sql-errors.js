export const tags = ['all'];

/**
 * SQL error disclosure check.
 *
 * Appends a single quote to common query parameters and scans the response
 * for database error messages. This is NOT a SQL injection exploit —
 * it only detects whether raw database errors leak to the browser,
 * which confirms an injection surface exists.
 */
const TEST_PAYLOADS = [
  "?id='",
  "?q='",
  "?search='",
  "?query='",
  "?user='",
  "?name='",
  "?filter='",
  "?page=1'",
];

const SQL_ERROR_PATTERNS = [
  // MySQL
  'you have an error in your sql syntax',
  'mysql_fetch_array()',
  'mysql_num_rows()',
  'supplied argument is not a valid mysql',
  'warning: mysql',
  // PostgreSQL
  'pg_query()',
  'pg::syntaxerror',
  'psql error',
  // MSSQL
  'microsoft ole db provider for sql server',
  'odbc sql server driver',
  'sqlserver error',
  'unclosed quotation mark',
  // Oracle
  'ora-01756',
  'ora-00907',
  'quoted string not properly terminated',
  // SQLite
  'sqlite_error',
  'sqlite3.operationalerror',
  // Generic
  'sqlstate',
  'sql syntax',
  'syntax error',
  'unterminated string literal',
];

export default async function run(target, fetchWithRetry) {
  for (const payload of TEST_PAYLOADS) {
    try {
      const res  = await fetchWithRetry(`${target}${payload}`);
      const body = res.text.toLowerCase();

      const matched = SQL_ERROR_PATTERNS.filter(p => body.includes(p));

      if (matched.length > 0) {
        return {
          name    : 'sql error disclosure',
          status  : 'VULNERABLE',
          severity: 'HIGH',
          detail  : `SQL error leaked via ${payload}: ${matched[0]}`,
          fix     : "Disable detailed database error messages in production. Implement parameterized queries or use an ORM to prevent SQL injection at the identified vulnerable parameter.",
          payload
        };
      }

    } catch { /* unreachable */ }
  }

  return { name: 'sql error disclosure', status: 'SAFE', severity: 'NONE' };
}
