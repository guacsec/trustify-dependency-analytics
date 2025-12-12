import {AppData} from '@app/api/report';

export const errorReport: AppData = {
  providerPrivateData: null ,
  report: {
    "scanned": {
      "total": 9,
      "direct": 2,
      "transitive": 7
    },
    "providers": {
      "trustify": {
        "status": {
          "ok": false,
          "name": "trustify",
          "code": 500,
          "message": "Unexpected error",
          "warnings": {}
        }
      }
    }
  },
  remediationTemplate: 'https://deps.dev/__PACKAGE_TYPE__/__PACKAGE_NAME__/__PACKAGE_VERSION__',
  cveIssueTemplate: 'https://nvd.nist.gov/vuln/detail/__ISSUE_ID__',
  imageMapping: "[\n" +
    "  {\n" +
    "    \"purl\": \"pkg:oci/ubi@sha256:f5983f7c7878cc9b26a3962be7756e3c810e9831b0b9f9613e6f6b445f884e74?repository_url=registry.access.redhat.com/ubi9/ubi&tag=9.3-1552&arch=amd64\",\n" +
    "    \"catalogUrl\": \"https://catalog.redhat.com/software/containers/ubi9/ubi/615bcf606feffc5384e8452e?architecture=amd64&image=65a82982a10f3e68777870b5\"\n" +
    "  },\n" +
    "  {\n" +
    "    \"purl\": \"pkg:oci/ubi-minimal@sha256:06d06f15f7b641a78f2512c8817cbecaa1bf549488e273f5ac27ff1654ed33f0?repository_url=registry.access.redhat.com/ubi9/ubi-minimal&tag=9.3-1552&arch=amd64\",\n" +
    "    \"catalogUrl\": \"https://catalog.redhat.com/software/containers/ubi9/ubi-minimal/615bd9b4075b022acc111bf5?architecture=amd64&image=65a828e3cda4984705d45d26\"\n" +
    "  }\n" +
    "]",
  userId: 'testUser003',
  anonymousId: null,
  writeKey: '',
  rhdaSource: 'vscode'
};
