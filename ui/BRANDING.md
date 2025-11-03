# Branding Configuration

This project supports flexible branding through backend environment variables. The system uses **default** branding and allows you to override specific elements as needed.

## Profile Configuration

The branding profiles are defined in `src/main/resources/application.properties`:

```properties
# Default branding configuration (Community/Trustify)
branding.display.name=Trustify
branding.explore.url=https://guac.sh/trustify/
branding.explore.title=Learn more about Trustify
branding.explore.description=The Trustify project is a collection of software components that enables you to store and retrieve Software Bill of Materials (SBOMs), and advisory documents.
branding.image.recommendation=
branding.image.remediation.link=

# Example: Custom organization branding profile
%myorg.branding.display.name=MyOrg
%myorg.branding.explore.url=https://example.com/security-tools
%myorg.branding.explore.title=Learn about MyOrg Security
%myorg.branding.explore.description=Explore our comprehensive security analysis tools and vulnerability management platform.
%myorg.branding.image.recommendation=Custom container image recommendations for enhanced security.
%myorg.branding.image.remediation.link=https://example.com/container-catalog
```

## Examples

### Method 1: Using Predefined Profile

To create a new branding profile for your organization:

1. **Add profile configuration** to `src/main/resources/application.properties`:
   ```properties
   # Replace 'myorg' with your organization identifier
   %myorg.branding.display.name=Your Organization Name
   %myorg.branding.explore.url=https://your-org.com/security
   %myorg.branding.explore.title=Learn about Your Org Security
   %myorg.branding.explore.description=Your custom description here.
   %myorg.branding.image.recommendation=Your custom container image recommendation text.
   %myorg.branding.image.remediation.link=https://your-org.com/container-catalog
   ```

2. **Use the profile** when running the application:
   ```bash
   ./mvnw quarkus:dev -Dquarkus.profile=myorg
   ```

3. **Override icons in private projects** using CSS to provide custom organization icons

### Method 2: Using Environment Variables

**Custom Organization Configuration:**
```bash
export BRANDING_DISPLAY_NAME="MyOrg"
export BRANDING_EXPLORE_URL="https://example.com/security-tools"
export BRANDING_EXPLORE_TITLE="Learn about MyOrg Security"
export BRANDING_EXPLORE_DESCRIPTION="Explore our comprehensive security analysis tools and vulnerability management platform."
export BRANDING_IMAGE_RECOMMENDATION="Custom container image recommendations for enhanced security."
export BRANDING_IMAGE_REMEDIATION_LINK="https://example.com/container-catalog"

./mvnw quarkus:dev
```

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
%myorg.branding.image.recommendation=Custom container image recommendations for enhanced security.
%myorg.branding.image.remediation.link=https://myorg.com/container-catalog
```

**Step 4: Build with your changes**
```bash
cd ui && npm run build
```

**Step 5: Run with your branding**
```bash
./mvnw quarkus:dev -Dquarkus.profile=myorg
```