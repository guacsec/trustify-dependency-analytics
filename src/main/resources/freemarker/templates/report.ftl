<!DOCTYPE html>
[#function htmlRef package]
    [#local result = package.name()?replace(".", "")]
    [#local result = result?replace(":","")]
    [#local result = result?replace("-","")]
    [#return result]
[/#function]
[#function repoLink package]
    [#local result = package.name()?replace(".", "/")]
    [#local result = result?replace(":", "/")]
    [#local result = body.remediationPath + result + "/" + package.version()]
    [#return result]
[/#function]
[#function packageLink package]
    [#return body.packagePath + package.name()?replace(":", "/") + "/" + package.version()]
[/#function]
[#function vexLink cve]
    [#return body.vexPath + cve + "-Quarkus.json" ]
[/#function]
<html lang="en-us">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <script>
        window["appData"]=[=body.appData];
    </script>
    <style>
        [#include "generated/vendor.css" parse="false"]
    </style>
    <style>
        [#include "generated/main.css" parse="false"]
    </style>
    <title>Dependency Analysis</title>
</head>

<body>
    <div id="root" class="pf-v5-u-h-100">
        <div
            class="pf-v5-u-display-flex pf-v5-u-flex-direction-column pf-v5-u-align-items-center pf-v5-u-justify-content-center pf-v5-u-h-100">
            <div>Loading...</div>
            <svg
                class="pf-v5-c-spinner"
                role="progressbar"
                viewBox="0 0 100 100"
                aria-label="Loading...">
                <circle
                    class="pf-v5-c-spinner__path"
                    cx="50"
                    cy="50"
                    r="45"
                    fill="none" />
            </svg>
        </div>
    </div>
    <script>
        [#include "generated/vendor.js" parse="false"]
    </script>
    <script>
        [#include "generated/main.js" parse="false"]
    </script>
</body>

</html>