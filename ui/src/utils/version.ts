import { VersionRange } from '../api/report';

export const formatRange = (range: VersionRange): string => {
  const parts: string[] = [];
  if (range.lowVersion) {
    parts.push(`${range.lowInclusive ? '>=' : '>'} ${range.lowVersion}`);
  }
  if (range.highVersion) {
    parts.push(`${range.highInclusive ? '<=' : '<'} ${range.highVersion}`);
  }
  return parts.join(', ') || 'Unknown range';
};

export const compareVersions = (a: string, b: string): number => {
  const partsA = a.split(/[.-]/);
  const partsB = b.split(/[.-]/);
  const len = Math.max(partsA.length, partsB.length);
  for (let i = 0; i < len; i++) {
    const sa = i < partsA.length ? partsA[i] : '';
    const sb = i < partsB.length ? partsB[i] : '';
    const na = /^\d+$/.test(sa) ? parseInt(sa, 10) : NaN;
    const nb = /^\d+$/.test(sb) ? parseInt(sb, 10) : NaN;
    if (!isNaN(na) && !isNaN(nb)) {
      if (na !== nb) return na - nb;
    } else if (!isNaN(na)) {
      return -1;
    } else if (!isNaN(nb)) {
      return 1;
    } else {
      const cmp = sa.localeCompare(sb, undefined, { sensitivity: 'base' });
      if (cmp !== 0) return cmp;
    }
  }
  return 0;
};
