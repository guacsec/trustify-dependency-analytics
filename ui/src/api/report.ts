export interface AppData {
  providerPrivateData?: string[] | null;
  report: Report | ReportMap;
  cveIssueTemplate: string;
  remediationTemplate: string;
  imageMapping: string;
  userId?: string | null;
  anonymousId?: string | null;
  writeKey?: string | null;
  rhdaSource?: string | null;
  brandingConfig?: BrandingConfig;
  advisoryIssueTemplate?: string;
}

export interface BrandingConfig {
  displayName: string;
  exploreUrl: string;
  exploreTitle: string;
  exploreDescription: string;
  imageRecommendation: string;
  imageRecommendationLink: string;
  advisoryIssueTemplate?: string;
}

export interface ReportMap {
  [key: string]: Report;
}

export interface Report {
  scanned: {
    direct: number;
    transitive: number;
    total: number;
  };
  providers: {
    [key: string]: {
      status: ProviderStatus;
      sources?: {
        [key: string]: SourceReport;
      };
    };
  };
  licenses?: LicenseReport[];
}

export interface LicenseReport {
  status: ProviderStatus
  summary: LicenseSummary;
  projectLicense?: LicenseInfo;
  packages: {
    [key: string]: LicensePackageReport;
  };
}

export interface LicensePackageReport {
  concluded: LicenseInfo;
  evidence: LicenseInfo[];
}

export interface LicenseInfo {
  identifiers: LicenseIdentifier[];
  expression: string;
  name: string;
  category: string;
  source: string;
  sourceUrl: string;
}

export interface LicenseIdentifier {
  id: string;
  name: string;
  isDeprecated?: boolean;
  isOsiApproved?: boolean;
  isFsfLibre?: boolean;
  category: string;
}

export interface LicenseSummary {
  total: number;
  concluded: number;
  permissive: number;
  strongCopyleft: number;
  unknown: number;
  weakCopyleft: number;
  deprecated: number;
  osiApproved: number;
  fsfLibre: number;
}

export interface ProviderStatus {
  ok: boolean;
  name: string;
  code: number;
  message: string | null;
  warnings: {
    [key: string]: string[];
  };
}

export interface Summary {
  direct: number;
  transitive: number;
  total: number;
  dependencies: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  remediations: number;
  recommendations: number;
  unscanned?: number;
}

export interface TransitiveDependency {
  ref: string;
  issues?: Vulnerability[];
  remediations?: {
    [key: string]: {
      issueRef: string;
      mavenPackage: string;
      productStatus: string;
    };
  };
  highestVulnerability: Vulnerability;
}

export interface Dependency {
  ref: string;
  issues?: Vulnerability[] | null;
  transitive?: TransitiveDependency[] | null;
  recommendation?: string | null;
  highestVulnerability?: Vulnerability | null;
}

export function getSources(report: Report): SourceItem[] {
  var result: SourceItem[] = [];
  Object.keys(report.providers).forEach((provider) => {
    const sources = report.providers[provider].sources;
    if (sources !== undefined && Object.keys(sources).length > 0) {
      Object.keys(sources).forEach((source) => {
        result.push({
          provider: provider,
          source: source,
          report: sources[source],
        } as SourceItem);
      });
    } else {
      if(provider !== 'trusted-content') {
        result.push({
          provider: provider,
          source: provider,
          report: {} as SourceReport,
        } as SourceItem);
      }
    }
  });
  return result.sort((a, b) => {
    if(Object.keys(a.report).length === 0 && Object.keys(b.report).length === 0) {
      return 1;
    }
    return Object.keys(b.report).length - Object.keys(a.report).length;
  });
}

export function getSourceName(item: SourceItem): string {
  if (!item || !item.provider) {
    return 'Other';
  }
  const provider = (!item.provider || item.provider === "unknown") ? "Other" : item.provider;
  const source = (!item.source || item.source === "unknown") ? "Other" : item.source;

  return provider === source ? provider : `${provider}/${source}`;
}

export function isReportMap(obj: any): boolean {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    Object.keys(obj).every((key) =>
      'scanned' in obj[key] &&
      'providers' in obj[key] &&
      typeof obj[key].scanned === 'object' &&
      typeof obj[key].providers === 'object'
    )
  );
}

export interface SourceItem {
  provider: string;
  source: string;
  report: SourceReport;
}

export interface SourceReport {
  summary: Summary;
  dependencies: Dependency[];
}

export interface VulnerabilityItem {
  id: string;
  dependencyRef: string;
  vulnerability: Vulnerability;
}

export interface Vulnerability {
  id: string;
  title?: string | undefined;
  source: string;
  cvss?: Cvss | null;
  cvssScore: number;
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  cves?: string[] | null;
  unique: boolean;
  remediation?: {
    fixedIn?: string[] | null;
    advisories?: AdvisoryRemediation[] | null;
    trustedContent?: {
      ref: string | '';
      status: string | null;
      justification: string | null;
    } | null;
  };
}

export interface Cvss {
  attackVector?: string;
  attackComplexity?: string;
  privilegesRequired?: string;
  userInteraction?: string;
  scope?: string;
  confidentialityImpact?: string;
  integrityImpact?: string;
  availabilityImpact?: string;
  exploitCodeMaturity?: string | null;
  remediationLevel?: string | null;
  reportConfidence?: string | null;
  cvss: string;
}

export type RemediationCategory =
  | 'VENDOR_FIX'
  | 'WORKAROUND'
  | 'MITIGATION'
  | 'NO_FIX_PLANNED'
  | 'NONE_AVAILABLE'
  | 'WILL_NOT_FIX';

export interface AdvisoryRemediation {
  advisory?: AdvisoryInfo;
  status?: string;
  versionRanges?: VersionRange[];
  fixedIn?: string;
  remediations?: RemediationInfo[];
}

export interface AdvisoryInfo {
  id: string;
  title?: string;
  url?: string;
}

export interface RemediationInfo {
  category?: RemediationCategory;
  details?: string;
  url?: string;
  advisory?: AdvisoryInfo;
}

export interface VersionRange {
  versionSchemeId?: string;
  lowVersion?: string;
  lowInclusive?: boolean;
  highVersion?: string;
  highInclusive?: boolean;
}

export interface CatalogEntry {
  purl: string;
  catalogUrl: string;
}

export function hasRemediations(vulnerability: Vulnerability): boolean {
  const rem = vulnerability.remediation;
  if (!rem) return false;
  return !!(
    (rem.fixedIn && rem.fixedIn.length > 0) ||
    rem.trustedContent ||
    (rem.advisories && rem.advisories.length > 0) ||
    rem.advisories?.some(a => a.remediations && a.remediations.length > 0)
  );
}

function mergeRemediation(
  existing: Vulnerability['remediation'],
  incoming: Vulnerability['remediation'],
): Vulnerability['remediation'] {
  if (!incoming) return existing;
  if (!existing) return incoming;

  const mergedFixedIn = (existing.fixedIn || []).concat(
    (incoming.fixedIn || []).filter(
      (v) => !(existing.fixedIn || []).includes(v),
    ),
  );

  const mergedAdvisories = (existing.advisories || []).concat(
    incoming.advisories || [],
  );

  return {
    fixedIn: mergedFixedIn.length > 0 ? mergedFixedIn : existing.fixedIn,
    advisories:
      mergedAdvisories.length > 0 ? mergedAdvisories : existing.advisories,
    trustedContent: existing.trustedContent || incoming.trustedContent,
  };
}

export function buildVulnerabilityItems(
  transitiveDependencies: TransitiveDependency[],
): VulnerabilityItem[] {
  const rowMap = new Map<string, VulnerabilityItem>();
  transitiveDependencies
    .map((transitive) => {
      return {
        dependencyRef: transitive.ref,
        vulnerabilities: transitive.issues || [],
      };
    })
    .forEach((item) => {
      item.vulnerabilities?.forEach((v) => {
        const ids =
          v.cves && v.cves.length > 0 ? v.cves : [v.id];
        ids.forEach((cveId) => {
          const key = cveId + '|' + item.dependencyRef;
          const existing = rowMap.get(key);
          if (existing) {
            existing.vulnerability = {
              ...existing.vulnerability,
              remediation: mergeRemediation(
                existing.vulnerability.remediation,
                v.remediation,
              ),
            };
          } else {
            rowMap.set(key, {
              id: cveId,
              dependencyRef: item.dependencyRef,
              vulnerability: { ...v },
            });
          }
        });
      });
    });
  const rows = Array.from(rowMap.values());
  return rows.sort((a, b) => b.vulnerability.cvssScore - a.vulnerability.cvssScore);
}
