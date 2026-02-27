/**
 * Shared license category constants and helpers.
 * Used by the license pie chart, category labels, and license tables so colors and labels stay consistent.
 */

import { LabelProps } from "@patternfly/react-core";

/** Same order as LicensesChartCard: permissive, weak copyleft, strong copyleft, unknown */
export const CATEGORY_COLORS: Record<string, string> = {
  PERMISSIVE: '#0066CC',
  WEAK_COPYLEFT: '#3E8635',
  STRONG_COPYLEFT: '#F0AB00',
  UNKNOWN: '#C46100',
};

export const CATEGORY_LABELS: Record<string, string> = {
  PERMISSIVE: 'Permissive',
  WEAK_COPYLEFT: 'Weak copyleft',
  STRONG_COPYLEFT: 'Strong copyleft',
  UNKNOWN: 'Unknown',
};


/** Category rank: higher = more permissive (PERMISSIVE=4, WEAK=3, STRONG=2, UNKNOWN=1). */
export function getCategoryRank(category: string | undefined): number {
  if (!category) return 1;
  const cat = category.toUpperCase().replace(/-/g, '_');
  switch (cat) {
    case 'PERMISSIVE':
      return 4;
    case 'WEAK_COPYLEFT':
      return 3;
    case 'STRONG_COPYLEFT':
      return 2;
    case 'UNKNOWN':
    default:
      return 1;
  }
}

export const WARNING_SHIELD_COLOR = '#F0AB00';

export function getCategoryLabel(category: string | undefined): string {
  if (!category) return CATEGORY_LABELS.UNKNOWN;
  const cat = category.toUpperCase().replace(/-/g, '_');
  return CATEGORY_LABELS[cat] ?? category;
}

export function getCategoryColor(category: string | undefined): string {
  if (!category) return CATEGORY_COLORS.UNKNOWN;
  const cat = category.toUpperCase().replace(/-/g, '_');
  return CATEGORY_COLORS[cat] ?? CATEGORY_COLORS.UNKNOWN;
}

export function getCategoryLabelColor(category: string | undefined): LabelProps['color'] {
  let color;
  if (!category) {
    color = "gray";
  } else {
    const cat = category.toUpperCase().replace(/-/g, '_');
    color = cat === "PERMISSIVE" ? "blue" : cat === "WEAK_COPYLEFT" ? "green" : cat === "STRONG_COPYLEFT" ? "yellow" : "gray";
  }
  return color as LabelProps['color'];
}

/** Sort order by decreasing permissiveness: Permissive first, then Weak copyleft, Strong copyleft, Unknown last. */
export const CATEGORY_SORT_ORDER = ['PERMISSIVE', 'WEAK_COPYLEFT', 'STRONG_COPYLEFT', 'UNKNOWN'] as const;

export function getCategorySortIndex(category: string | undefined): number {
  if (!category) return CATEGORY_SORT_ORDER.length;
  const cat = category.toUpperCase().replace(/-/g, '_');
  const idx = CATEGORY_SORT_ORDER.indexOf(cat as (typeof CATEGORY_SORT_ORDER)[number]);
  return idx >= 0 ? idx : CATEGORY_SORT_ORDER.length;
}
