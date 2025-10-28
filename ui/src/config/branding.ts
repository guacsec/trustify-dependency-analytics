export interface BrandingConfig {
  mode: 'redhat' | 'community';
  brandName: string;
  title: string;
  remediationTitle: string;
  icon: string;
  url: string;
  exploreTitle: string;
  exploreDescription: string;
}

export const getBrandingConfig = (): BrandingConfig => {
  const mode = (process.env.REACT_APP_BRANDING_MODE as 'redhat' | 'community') || 'community';

  // Define defaults based on mode
  const defaults = {
    community: {
      brandName: 'Trustify',
      title: 'Trustify Overview of security issues',
      remediationTitle: 'Remediations',
      icon: 'trustify',
      url: 'https://guac.sh/trustify/',
      exploreTitle: 'Learn more about Trustify',
      exploreDescription: 'The Trustify project is a collection of software components that enables you to store and retrieve Software Bill of Materials (SBOMs), and advisory documents.'
    },
    redhat: {
      brandName: 'Red Hat',
      title: 'Red Hat Overview of security Issues',
      remediationTitle: 'Red Hat Remediations',
      icon: 'redhat',
      url: 'https://developers.redhat.com/products/trusted-profile-analyzer/overview',
      exploreTitle: 'Join to explore Red Hat TPA',
      exploreDescription: 'Check out our new Trustify to get visibility and insight into your software risk profile, for instance by exploring vulnerabilites or analyzing SBOMs.'
    }
  };

  const modeDefaults = defaults[mode];

  return {
    mode,
    brandName: process.env.REACT_APP_BRAND_NAME || modeDefaults.brandName,
    title: process.env.REACT_APP_BRAND_TITLE || modeDefaults.title,
    remediationTitle: process.env.REACT_APP_REMEDIATION_TITLE || modeDefaults.remediationTitle,
    icon: process.env.REACT_APP_BRAND_ICON || modeDefaults.icon,
    url: process.env.REACT_APP_BRAND_URL || modeDefaults.url,
    exploreTitle: process.env.REACT_APP_EXPLORE_TITLE || modeDefaults.exploreTitle,
    exploreDescription: process.env.REACT_APP_EXPLORE_DESCRIPTION || modeDefaults.exploreDescription
  };
};