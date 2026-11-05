// Heuristic password-strength estimate shown while typing. It is advice for the user:
// the server never sees the password, so this check is necessarily client-side.

const COMMON = new Set([
  'password', 'passw0rd', 'qwerty', 'qwertyuiop', 'letmein', 'welcome', 'admin', 'administrator',
  'iloveyou', 'monkey', 'dragon', 'football', 'baseball', 'abc', 'abcdef', 'login', 'master',
  'sunshine', 'princess', 'trustno', 'alfamail', 'haslo', 'polska', 'zaq', 'qazwsx', 'changeme',
  'secret', 'superman', 'batman', 'starwars', 'whatever', 'freedom', 'shadow', 'mustang',
]);

export const MIN_LENGTH = 12;
const LABELS = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'];

function poolSize(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  return pool || 1;
}

// Repeated characters and simple runs (abc, 123, aaa) add far less than a random character.
function effectiveLength(pw) {
  let total = 0;
  for (let i = 0; i < pw.length; i++) {
    const c = pw.charCodeAt(i);
    const p1 = i > 0 ? pw.charCodeAt(i - 1) : null;
    const p2 = i > 1 ? pw.charCodeAt(i - 2) : null;
    if (p1 === c) total += 0.15;
    else if (p1 !== null && p2 !== null && c - p1 === p1 - p2 && Math.abs(c - p1) === 1) total += 0.3;
    else total += 1;
  }
  return total;
}

export function assessPassword(pw, username = '') {
  const issues = [];
  if (pw.length < MIN_LENGTH) issues.push(`Use at least ${MIN_LENGTH} characters.`);

  const lower = pw.toLowerCase();
  const lettersOnly = lower.replace(/[^a-z]/g, '');
  if (COMMON.has(lower) || COMMON.has(lettersOnly)) issues.push('This is based on a very common password.');
  const user = username.trim().toLowerCase();
  if (user.length >= 3 && lower.includes(user)) issues.push('Do not include your username.');
  if (new Set(pw).size < 5 && pw.length > 0) issues.push('Use more different characters.');

  const bits = effectiveLength(pw) * Math.log2(poolSize(pw));
  let score = bits < 28 ? 0 : bits < 44 ? 1 : bits < 60 ? 2 : bits < 76 ? 3 : 4;
  if (issues.length) score = Math.min(score, 1);
  if (!pw) score = 0;

  return { score, label: LABELS[score], issues, acceptable: issues.length === 0 && score >= 3 };
}
