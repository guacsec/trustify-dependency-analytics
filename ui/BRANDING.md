# Branding Configuration

This project supports two branding modes: **Red Hat** (enterprise) and **Community** (Trustify).

## Quick Start

### Prerequisites
Install the `env-cmd` package to enable environment-specific builds:
```bash
npm install --save-dev env-cmd
```

### Development
```bash
# Start development server with Community branding (default)
npm run start:community

# Start development server with Red Hat branding
npm run start:redhat
```

### Production Build
```bash
# Build Community version
npm run build:community

# Build Red Hat version
npm run build:redhat
```

## Configuration Files

### `.env.community` - Community/Trustify Version
- Uses Trustify branding
- Points to https://guac.sh/trustify/
- Shows "Trustify Overview of security issues"
- Uses Trustify icon for remediations

### `.env.redhat` - Red Hat Enterprise Version
- Uses Red Hat branding
- Points to Red Hat developer portal
- Shows "Red Hat Overview of security Issues"
- Uses Red Hat icon for remediations
- Includes "from Red Hat" in remediation text

## How It Works

1. **Environment Variables**: Different `.env` files define branding configuration
2. **Branding Config**: `src/config/branding.ts` reads environment variables and provides typed configuration
3. **Conditional Rendering**: Components use `getBrandingConfig()` to conditionally render content based on branding mode

## Customizing Branding

To modify branding, edit the respective `.env` file:

```bash
REACT_APP_BRANDING_MODE=community|redhat
REACT_APP_BRAND_NAME=Your Brand Name
REACT_APP_BRAND_TITLE=Your Overview Title
REACT_APP_REMEDIATION_TITLE=Your Remediation Title
REACT_APP_BRAND_ICON=icon_name
REACT_APP_BRAND_URL=https://your-url.com
REACT_APP_EXPLORE_TITLE=Your Explore Title
REACT_APP_EXPLORE_DESCRIPTION=Your description text
```