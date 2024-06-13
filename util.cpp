#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include "util.h"

#include <aws/core/Aws.h>
#include <aws/core/client/ClientConfiguration.h>

Aws::Client::ClientConfiguration create_aws_config(std::string region) {
    Aws::Client::ClientConfiguration awsConfig;

#ifdef AWS_SDK_USE_SYSTEM_PROXY
    awsConfig.allowSystemProxy = true;
#endif

    if (region.length() > 0) {
        awsConfig.region = region;
    }

    const char* endpoint = std::getenv("AWS_ENDPOINT_URL");
    if (endpoint != nullptr) {
        const char* prefix = "https";
        awsConfig.enableEndpointDiscovery = false;

        std::string url(endpoint);
        std::string::size_type pos = url.find("://");
        if (pos != std::string::npos) {
            // Remove the scheme part (e.g., "http://")
            url = url.substr(pos + 3);
        }
        awsConfig.endpointOverride = Aws::String(url);
        awsConfig.scheme = (strncmp(endpoint, prefix, strlen(prefix)) == 0) ? Aws::Http::Scheme::HTTPS : Aws::Http::Scheme::HTTP;
        awsConfig.verifySSL = (strncmp(endpoint, prefix, strlen(prefix)) == 0) ? true : false;
    }

    return awsConfig;
}
