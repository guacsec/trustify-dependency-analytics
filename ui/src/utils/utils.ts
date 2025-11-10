import {AppData, CatalogEntry, getSources, ProviderStatus, Report} from "../api/report";

const MAVEN_TYPE = 'maven';
const MAVEN_URL = 'https://central.sonatype.com/artifact/';

const GOLANG_TYPE = 'golang';
const GOLANG_URL = 'https://pkg.go.dev/';

const NPM_TYPE = 'npm';
const NPM_URL = 'https://www.npmjs.com/package/'

const PYPI_TYPE = 'pypi';
const PYPI_URL = 'https://pypi.org/project/';

const DEBIAN_TYPE = 'deb';
const DEBIAN_URL = 'https://sources.debian.org/patches/';

const ISSUE_PLACEHOLDER = '__ISSUE_ID__';

const PURL_PKG_PREFIX = 'pkg:';

const SIGN_UP_TAB_PROVIDERS = ['oss-index'];

const OSS_SIGN_UP_LINK = 'https://ossindex.sonatype.org/user/register';

const ENCODED_CHAR_REGEX = /%[0-9A-Fa-f]{2}/;

export const getSignUpLink = (provider: string): string => {
  switch(provider) {
    case 'oss-index': return OSS_SIGN_UP_LINK;
  }
  return '';
}

export const hasSignUpTab = (provider: ProviderStatus): boolean => {
  if(!provider.ok && provider.code === 401 && provider.message === 'Unauthenticated') {
    return SIGN_UP_TAB_PROVIDERS.includes(provider.name);
  }
  return false;
}

const extractName = (pkgUrl: PackageURL): string => {
  let result = '';
  if(pkgUrl.namespace) {
    if(pkgUrl.type === MAVEN_TYPE) {
      result = `${pkgUrl.namespace}:`;
    } else {
      result = `${pkgUrl.namespace}/`;
    }
  }
  result += `${pkgUrl.name}`;
  return result;
}

export const extractDependencyName = (name: string, showVersion: boolean) => {
  const pkgUrl = PackageURL.fromString(name);
  let result = extractName(pkgUrl);
  const decodedVersion = pkgUrl.version ? decodeURIComponent(pkgUrl.version) : '';
  if(showVersion) {
    return result + `@${decodedVersion}`;
  }
  return result;
};

export const tcRemediationLink = (name: string) => {
  const pkgUrl = PackageURL.fromString(name);
  if(pkgUrl.qualifiers && pkgUrl.qualifiers.has('repository_url')) {
    let repositoryUrl = decodeURIComponent(pkgUrl.qualifiers.get('repository_url') || '');
    if(repositoryUrl.endsWith('/')) {
      repositoryUrl = repositoryUrl.substring(0, repositoryUrl.length - 1);
    }
    let namespace = pkgUrl.namespace;
    if(namespace) {
      namespace = namespace.replace(/\./g, "/");
    }
    return `${repositoryUrl}/${namespace}/${pkgUrl.name}/${pkgUrl.version}`;
  }
  let result = MAVEN_URL;
  if(pkgUrl.namespace) {
    return `${MAVEN_URL}${pkgUrl.namespace}/${pkgUrl.name}/${pkgUrl.version}`;
  }
  return result;
};

export const extractDependencyUrl = (name: string) => {
  const pkgUrl = PackageURL.fromString(name);
  switch(pkgUrl.type) {
    case MAVEN_TYPE:
      return `${MAVEN_URL}${pkgUrl.namespace}/${pkgUrl.name}/${pkgUrl.version}`;
    case GOLANG_TYPE:
      const version = pkgUrl.version;
      if(version?.match(/v\d\.\d.\d-\d{14}-\w{12}/)) { //pseudo-version
        return `${GOLANG_URL}${pkgUrl.namespace}/${pkgUrl.name}`;
      }
      return `${GOLANG_URL}${pkgUrl.namespace}/${pkgUrl.name}@${pkgUrl.version}`;
    case NPM_TYPE:
      if(pkgUrl.namespace) {
        return `${NPM_URL}${pkgUrl.namespace}/${pkgUrl.name}/v/${pkgUrl.version}`
      }
      return `${NPM_URL}${pkgUrl.name}/v/${pkgUrl.version}`
    case PYPI_TYPE:
      if(pkgUrl.namespace) {
        return `${PYPI_URL}${pkgUrl.namespace}/${pkgUrl.name}/${pkgUrl.version}`
      }
      return `${PYPI_URL}${pkgUrl.name}/${pkgUrl.version}`
    case DEBIAN_TYPE:
      return `${DEBIAN_URL}${pkgUrl.name}/${pkgUrl.version}`
    default: return pkgUrl.toString();
  }
};

export const extractDependencyVersion = (name: string): string => {
  const version = PackageURL.fromString(name).version;
  return version ? decodeURIComponent(version) : '';
};

export const issueLink = (provider: string, issueId: string, appData: AppData) => {
  return appData.nvdIssueTemplate.replace(ISSUE_PLACEHOLDER, issueId);
};

export const cveLink = (issueId: string, appData: AppData) => {
  return appData.cveIssueTemplate.replace(ISSUE_PLACEHOLDER, issueId);
}

export const uppercaseFirstLetter = (val: string) => {
  return val.toLowerCase().replace(/./, (c) => c.toUpperCase());
};

export const constructImageName = (purl: string): string => {
  const purlObj = parsePurl(purl);
  let imageName = '';
  if (purlObj.repository_url) {
    const indexOfFirstSlash = purlObj.repository_url.indexOf("/");
    const parsedRepoUrl = indexOfFirstSlash !== -1 ? purlObj.repository_url.substring(indexOfFirstSlash + 1) : "";
    imageName += parsedRepoUrl;
  } else {
    imageName += `${purlObj.short_name}`;
  }
  if (purlObj.tag) {
    imageName += `:${purlObj.tag}`;
  }
  return imageName;
}

const parsePurl = (purl: string) =>{
  const parts = purl.split('?');
  const nameVersion = parts[0];
  const queryParams = parts[1];
  const query = new URLSearchParams(queryParams);

  const repository_url = query.get('repository_url') || '';
  const tag = query.get('tag') || '';
  const arch = query.get('arch') || '';
  const atIndex = nameVersion.split("@");
  const short_name = atIndex[0].substring(atIndex[0].indexOf("/") + 1);
  // Extract version and replace "%" with ":"
  const version = nameVersion.substring(nameVersion.lastIndexOf("@")).replace("%3A", ":");

  return { repository_url, tag, short_name, version, arch };
}

const isEncoded = (str: string): boolean => {
  return ENCODED_CHAR_REGEX.test(str);
}

export const imageRecommendationLink = (purl: string, report: Report, imageMapping: string, imageRecommendationLink?: string) => {
  const sources = getSources(report);
  let result = imageRecommendationLink || '';

  for (const key in sources) {
    const source = sources[key];
    const dependencies = source.report.dependencies;
    if (dependencies) {
      // Find the Dependency with matching ref to the provided purl
      const matchingDependency = Object.values(dependencies).find(dependency => {
      const originalRef = dependency.ref;
      const transformedRef = decodeURIComponent(originalRef);
      const transformedPurl = isEncoded(purl) ? decodeURIComponent(purl) : purl;

      return PackageURL.fromString(transformedRef).toString() === PackageURL.fromString(transformedPurl).toString();
    });

      if (matchingDependency && matchingDependency.recommendation && result) {
        const transformedRecommUrl = decodeURIComponent(matchingDependency.recommendation);
        const catalogUrl = getCatalogUrlByPurl(transformedRecommUrl, imageMapping);

        if (catalogUrl !== undefined) {
          // Extract image name from the recommendation purl to construct the final URL
          const imageName = constructImageName(transformedRecommUrl);
          return result + imageName;
        }
      }
    }
  }
  return result;
};

const getCatalogUrlByPurl = (recommendPurl: string, imageMapping: string): string | undefined => {
  const catalogEntries: CatalogEntry[] = JSON.parse(imageMapping);
  // Find the matching entry
  const matchingEntry = catalogEntries.find(entry => PackageURL.fromString(entry.purl).toString() === PackageURL.fromString(recommendPurl).toString());

  return matchingEntry?.catalogUrl;
};

class PackageURL {

  readonly type: string;
  readonly namespace: string | undefined | null;
  readonly name: string;
  readonly version: string | undefined | null;
  readonly qualifiers: Map<string, string> | undefined | null;

  constructor(type: string,
    namespace: string | undefined | null,
    name: string,
    version: string | undefined | null,
    qualifiers: Map<string, string> | undefined | null) {
      this.type = type;
      this.namespace = namespace;
      this.name = name;
      this.version = version;
      this.qualifiers = qualifiers;
    }

  toString(): string {
    let name = this.name;
    if(this.version) {
      name += `@${this.version}`;
    }
    if(this.namespace) {
      return `${PURL_PKG_PREFIX}${this.type}/${this.namespace}/${name}`;
    }
    if(this.qualifiers) {
      return `${PURL_PKG_PREFIX}${this.type}/${name}?${Array.from(this.qualifiers.entries()).map(([key, value]) => `${key}=${value}`).join('&')}`;
    }
    return `${PURL_PKG_PREFIX}${this.type}/${name}`;
  }

  static fromString(purl: string): PackageURL {
    let value = purl.replace(PURL_PKG_PREFIX, '');
    let qualifiers;
    const qualifiersIdx = value.indexOf('?');
      if(qualifiersIdx !== -1) {
        qualifiers = value.substring(qualifiersIdx + 1);
        value = value.substring(0, qualifiersIdx);
      }
    const type = value.substring(0, value.indexOf('/'));
    const parts = value.split('/');
    let namespace;
    if(parts.length > 2) {
      namespace = parts.slice(1, parts.length - 1).join('/');
    }
    let version;
    if(value.indexOf('@') !== -1) {
      version = value.substring(value.indexOf('@') + 1);
    }
    let name = parts[parts.length - 1];
    if(version) {
      name = name.substring(0, name.indexOf('@'));
    }
    return new PackageURL(type, namespace, name, version, new Map(qualifiers?.split('&').map(q => q.split('=') as [string, string]) || []));
  }

}
