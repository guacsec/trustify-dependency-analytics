# Branding Configuration

This project supports flexible branding through backend environment variables. The system uses **default** branding and allows you to override specific elements as needed.

## Quick Start

### Using Predefined Profiles

**Default branding:**
```bash
# Default profile - no additional flags needed
./mvnw quarkus:dev
```

**Custom organization branding:**
```bash
# Example using a custom profile (e.g., myorg)
./mvnw quarkus:dev -Dquarkus.profile=myorg
```

### Using Environment Variables (Alternative)
```bash
# Start development server (branding controlled by backend environment variables)
npm start
```

### Production Build
```bash
# Build for production (branding controlled by backend environment variables)
npm run build
```

## How It Works

1. **Backend Configuration**: Java backend reads `BRANDING_XXX` environment variables
2. **Runtime Injection**: Branding configuration is passed to the React app through `appData`
3. **Component Usage**: React components read branding configuration from the app context
4. **Default-First**: All defaults are set to standard values, specific brands override as needed

## Available Environment Variables

Configure branding by setting these environment variables for the Java backend:

```bash
# Brand identity
BRANDING_DISPLAY_NAME=Your Brand Name           # Used for conditional logic and remediation title

# Explore section
BRANDING_EXPLORE_URL=https://your-url.com       # URL for "Take me there" button
BRANDING_EXPLORE_TITLE=Your Explore Title             # Title for explore section
BRANDING_EXPLORE_DESCRIPTION=Your description text    # Description text
```

## Branding Logic

The system uses `displayName` for all branding decisions:

- **Custom organization branding**: Uses the provided `displayName` (e.g., "MyOrg" shows "MyOrg Remediations")
- **Default branding**: Used when no custom branding is configured

## Icon System

The system uses a CSS-based icon override approach:

- **Default icon**: Built-in Trustify logo (PNG)
- **Custom icons**: Organizations can override the default icon using CSS in their private projects

## Examples

### Method 1: Using Predefined Profile

**Default branding:**
```bash
# Default behavior (no profile needed)
./mvnw quarkus:dev
```

**Custom organization branding:**
```bash
# Example using a custom profile
./mvnw quarkus:dev -Dquarkus.profile=myorg
```

**Production builds with profiles:**
```bash
# Default production build
./mvnw clean package

# Custom organization production build
./mvnw clean package -Dquarkus.profile=myorg
```

### Method 2: Using Environment Variables

**Default Configuration (no environment variables needed):**
```bash
# No environment variables needed - uses default Trustify branding
./mvnw quarkus:dev
```

**Custom Organization Configuration:**
```bash
export BRANDING_DISPLAY_NAME="MyOrg"
export BRANDING_EXPLORE_URL="https://example.com/security-tools"
export BRANDING_EXPLORE_TITLE="Learn about MyOrg Security"
export BRANDING_EXPLORE_DESCRIPTION="Explore our comprehensive security analysis tools and vulnerability management platform."

./mvnw quarkus:dev
```

## Backend Integration

The branding configuration is handled using Quarkus `@ConfigMapping`:

**BrandingConfig.java:**
```java
@ConfigMapping(prefix = "branding")
public interface BrandingConfig {
  String displayName();
  String exploreUrl();
  String exploreTitle();
  String exploreDescription();
}
```

**ReportTemplate.java:**
```java
@Inject Optional<BrandingConfig> brandingConfig;

// Only include branding config if it's present
brandingConfig.ifPresent(config -> params.put("brandingConfig", getBrandingConfigMap(config)));
```

The configuration is then passed to the frontend via the `appData` object in the Freemarker template.

## Profile Configuration

The branding profiles are defined in `src/main/resources/application.properties`:

```properties
# Default branding configuration (Community/Trustify)
branding.display.name=Trustify
branding.explore.url=https://guac.sh/trustify/
branding.explore.title=Learn more about Trustify
branding.explore.description=The Trustify project is a collection of software components that enables you to store and retrieve Software Bill of Materials (SBOMs), and advisory documents.

# Example: Custom organization branding profile
%myorg.branding.display.name=MyOrg
%myorg.branding.explore.url=https://example.com/security-tools
%myorg.branding.explore.title=Learn about MyOrg Security
%myorg.branding.explore.description=Explore our comprehensive security analysis tools and vulnerability management platform.
```

## Creating Custom Branding Profiles

To create a new branding profile for your organization:

1. **Add profile configuration** to `src/main/resources/application.properties`:
   ```properties
   # Replace 'myorg' with your organization identifier
   %myorg.branding.display.name=Your Organization Name
   %myorg.branding.explore.url=https://your-org.com/security
   %myorg.branding.explore.title=Learn about Your Org Security
   %myorg.branding.explore.description=Your custom description here.
   ```

2. **Use the profile** when running the application:
   ```bash
   ./mvnw quarkus:dev -Dquarkus.profile=myorg
   ```

3. **Override icons in private projects** using CSS to provide custom organization icons

Environment variables will override profile settings if both are provided.

## Custom Icon Implementation

To implement a completely custom icon for your organization, follow this step-by-step guide:

**Step 1: Add your custom icon**
```bash
# Copy your organization's icon to the UI assets directory
cp /path/to/myorg.png /path/to/trustify-dependency-analytics/ui/src/images/myorg.png
```

**Step 2: Create CSS override**
Add the following CSS to `/ui/src/index.css`:
```css
/* Custom icon override - Replace Trustify icon with MyOrg icon */
img[alt="My Org Icon"] {
  content: url('./images/myorg.png') !important;
  width: 16px !important;
  height: 16px !important;
}
```

**Step 3: Configure organization branding**
Add to `/src/main/resources/application.properties`:
```properties
# MyOrg custom branding profile
%myorg.branding.display.name=MyOrg
%myorg.branding.explore.url=https://myorg.com/security
%myorg.branding.explore.title=Learn about MyOrg Security
%myorg.branding.explore.description=Explore our comprehensive security analysis tools and vulnerability management platform.
```

**Step 4: Build with your changes**
```bash
cd ui && npm run build
```

**Step 5: Run with your branding**
```bash
./mvnw quarkus:dev -Dquarkus.profile=myorg
```