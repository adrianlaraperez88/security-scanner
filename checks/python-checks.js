export const tags = ['python', 'django', 'flask', 'all'];

/**
 * Specialized checks for Python web ecosystems.
 * Python apps often leak internal metadata through requirements files, 
 * virtual environment directories, and highly detailed debug pages.
 */
const CHECKS = [
  {
    path: '/requirements.txt',
    name: 'python requirements disclosure',
    severity: 'MEDIUM',
    reason: 'Reveals full list of dependencies and versions — helps attackers identify CVEs.',
    signals: ['django', 'flask', 'requests', 'gunicorn', '==', '>=']
  },
  {
    path: '/pip-log.txt',
    name: 'pip install log exposure',
    severity: 'MEDIUM',
    reason: 'Leaks installation history and potentially local paths.',
    signals: ['pip install', 'Downloading', 'Successfully installed']
  },
  {
    path: '/__pycache__/',
    name: 'python bytecode cache exposure',
    severity: 'MEDIUM',
    reason: 'Reveals internal directory structure and compiled file names.',
    signals: ['Index of', '.pyc', '__pycache__']
  },
  {
    path: '/venv/bin/activate',
    name: 'python virtualenv exposure',
    severity: 'HIGH',
    reason: 'Reveals that a virtual environment is improperly exposed in the web root.',
    signals: ['VIRTUAL_ENV', 'deactivate']
  },
  {
    path: '/.env/bin/activate',
    name: 'python virtualenv exposure (hidden)',
    severity: 'HIGH',
    reason: 'Reveals an improperly exposed virtual environment (hidden directory).',
    signals: ['VIRTUAL_ENV', 'deactivate']
  }
];

export default async function run(target, fetchWithRetry) {
  const found = [];

  // 1. Static file/directory checks
  for (const check of CHECKS) {
    try {
      const res = await fetchWithRetry(`${target}${check.path}`);
      if (res.status === 200) {
        const isReal = check.signals.some(s => res.text.includes(s)) || 
                       (check.path.endsWith('/') && res.text.toLowerCase().includes('index of'));
        if (isReal) {
          found.push({ ...check, status: 'VULNERABLE' });
        }
      }
    } catch { /* ignore */ }
  }

  // 2. Framework Debug Mode detection
  // Query a non-existent path to trigger a 404/Error page
  try {
    const probe = await fetchWithRetry(`${target}/_non_existent_path_${Math.random().toString(36).substring(7)}`);
    const txt = probe.text.toLowerCase();
    
    // Django DEBUG=True check
    if (txt.includes('django') && txt.includes('debug') && txt.includes('using the urlconf defined in')) {
      found.push({
        name: 'django debug mode enabled',
        severity: 'CRITICAL',
        reason: 'Django is running with DEBUG=True. This leaks your entire URL structure, settings, and environment variables.',
        status: 'VULNERABLE'
      });
    }

    // Flask/Werkzeug Debugger check
    if (txt.includes('werkzeug debugger') || txt.includes('the debugger is active') || txt.includes('debugger pin')) {
      found.push({
        name: 'flask/werkzeug debugger active',
        severity: 'CRITICAL',
        reason: 'The Flask/Werkzeug interactive debugger is active. This often allows remote code execution (RCE) via the debug console.',
        status: 'VULNERABLE'
      });
    }
  } catch { /* ignore */ }

  if (found.length === 0) {
    return { name: 'python security', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = found.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
               : found.some(f => f.severity === 'HIGH')     ? 'HIGH'
               : 'MEDIUM';

  return {
    name    : 'python security',
    status  : 'VULNERABLE',
    severity: maxSev,
    findings: found.map(f => ({ name: f.name, severity: f.severity, reason: f.reason })),
    fix     : 'Move requirements.txt and virtualenvs outside the web root. Ensure DEBUG=False in production for Django/Flask, and never expose the Werkzeug debugger to the public internet.'
  };
}
