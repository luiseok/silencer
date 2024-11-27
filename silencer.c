#include "utils.h"

// The "unblockall" feature will delete all filters that are based on the custom filter name
WCHAR* filterName = L"Custom Outbound Filter";
WCHAR* providerName = L"Microsoft Corporation";
// provider description has to be unique because:
// - avoid problem in adding persistent WFP filter to a provider (error 0x80320016)
// - avoid removing legitimate WFP provider
WCHAR* providerDescription = L"Microsoft Windows WFP Built-in custom provider.";

// Remove all WFP filters previously created
void UnblockAllWfpFilters() {
    HANDLE hEngine = NULL;
    DWORD result = 0;
    HANDLE enumHandle = NULL;
    FWPM_FILTER0** filters = NULL;
    GUID providerGuid = {0};
    UINT32 numFilters = 0;
    BOOL foundFilter = FALSE;
    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmEngineOpen0 failed with error code: 0x%x.\n", result);
        return;
    }

    result = FwpmFilterCreateEnumHandle0(hEngine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmFilterCreateEnumHandle0 failed with error code: 0x%x.\n", result);
        return;
    }

    while(TRUE) {
        result = FwpmFilterEnum0(hEngine, enumHandle, 1, &filters, &numFilters);

        if (result != ERROR_SUCCESS) {
            printf("[-] FwpmFilterEnum0 failed with error code: 0x%x.\n", result);
            FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
            FwpmEngineClose0(hEngine);
            return;
        }

        if (numFilters == 0) {
			break;
        }
        
        FWPM_DISPLAY_DATA0 *data = &filters[0]->displayData;
        WCHAR* currentFilterName = data->name;
        if (wcscmp(currentFilterName, filterName) == 0) {
            foundFilter = TRUE;
            UINT64 filterId = filters[0]->filterId;
            result = FwpmFilterDeleteById0(hEngine, filterId);
            if (result == ERROR_SUCCESS) {
                printf("Deleted filter id: %llu.\n", filterId);
            } else {
                printf("[-] Failed to delete filter id: %llu with error code: 0x%x.\n", filterId, result);
            }
        }
    }

    if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
        result = FwpmProviderDeleteByKey0(hEngine, &providerGuid);
        if (result != ERROR_SUCCESS) {
            if (result != FWP_E_IN_USE) {
                printf("[-] FwpmProviderDeleteByKey0 failed with error code: 0x%x.\n", result);
            }
        } else {
            printf("Deleted custom WFP provider.\n");
        }
    }

    if (!foundFilter) {
        printf("[-] Unable to find any WFP filter created by this tool.\n");
    }
    FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
    FwpmEngineClose0(hEngine);
}

// Remove WFP filter based on filter id
void UnblockWfpFilter(UINT64 filterId) {
    HANDLE hEngine = NULL;
    DWORD result = 0;
    GUID providerGuid = {0};

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmEngineOpen0 failed with error code: 0x%x.\n", result);
        return;
    }
    
    result = FwpmFilterDeleteById0(hEngine, filterId);

    if (result == ERROR_SUCCESS) {
        printf("Deleted filter id: %llu.\n", filterId);
    }
    else if (result == FWP_E_FILTER_NOT_FOUND) {
        printf("[-] The filter does not exist.\n");
    } else {
        printf("[-] Failed to delete filter id: %llu with error code: 0x%x.\n", filterId, result);
    }

    if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
        result = FwpmProviderDeleteByKey0(hEngine, &providerGuid);
        if (result != ERROR_SUCCESS) {
            if (result != FWP_E_IN_USE) {
                printf("[-] FwpmProviderDeleteByKey0 failed with error code: 0x%x.\n", result);
            }
        } else {
            printf("Deleted custom WFP provider.\n");
        }
    }

    FwpmEngineClose0(hEngine);
}

// Blocking process with pid
void BlockProcessByPID(DWORD pid) {
    DWORD result = 0;
    HANDLE hEngine = NULL;
    HANDLE hProcess = NULL;
    WCHAR fullPath[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    FWPM_FILTER_CONDITION0 cond = {0};
    FWPM_FILTER0 filter = {0};
    FWPM_PROVIDER0 provider = {0};
    GUID providerGuid = {0};
    FWP_BYTE_BLOB* appId = NULL;
    UINT64 filterId = 0;
    ErrorCode errorCode = CUSTOM_SUCCESS;
    
    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmEngineOpen0 failed with error code: 0x%x.\n", result);
        return;
    }

    // Obtain process handle with PID
    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        printf("[-] Could not open process with PID %d. Error code: 0x%x.\n", pid, GetLastError());
        FwpmEngineClose0(hEngine);
        return;
    }

    // Get full path of a Process
    if (!QueryFullProcessImageNameW(hProcess, 0, fullPath, &size)) {
        printf("[-] Could not get process path. Error code: 0x%x.\n", GetLastError());
        CloseHandle(hProcess);
        FwpmEngineClose0(hEngine);
        return;
    }

    errorCode = CustomFwpmGetAppIdFromFileName0(fullPath, &appId);
    if (errorCode != CUSTOM_SUCCESS) {
        printf("[-] Failed to get AppID for process. Error code: %d\n", errorCode);
        CloseHandle(hProcess);
        FwpmEngineClose0(hEngine);
        return;
    }

    // Set FWP filter
    filter.displayData.name = filterName;
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_BLOCK;
    UINT64 weightValue = 0xFFFFFFFFFFFFFFFF;
    filter.weight.type = FWP_UINT64;
    filter.weight.uint64 = &weightValue;
    cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    cond.conditionValue.byteBlob = appId;
    filter.filterCondition = &cond;
    filter.numFilterConditions = 1;

    // WFP provider 추가
    if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
        filter.providerKey = &providerGuid;
    } else {
        provider.displayData.name = providerName;
        provider.displayData.description = providerDescription;
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        result = FwpmProviderAdd0(hEngine, &provider, NULL);
        if (result == ERROR_SUCCESS) {
            if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
                filter.providerKey = &providerGuid;
            }
        }
    }

    // add IPv4 filter
    result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) {
        printf("Added WFP filter for PID %d (\"%S\") (Filter id: %d, IPv4 layer).\n", 
               pid, fullPath, filterId);
    } else {
        printf("[-] Failed to add IPv4 filter. Error code: 0x%x.\n", result);
    }

    // add IPv6 filter
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) {
        printf("Added WFP filter for PID %d (\"%S\") (Filter id: %d, IPv6 layer).\n", 
               pid, fullPath, filterId);
    } else {
        printf("[-] Failed to add IPv6 filter. Error code: 0x%x.\n", result);
    }

    FreeAppId(appId);
    CloseHandle(hProcess);
    FwpmEngineClose0(hEngine);
}

void PrintHelp() {
    printf("Usage: silencer.exe <block/unblockall/unblock> [args]\n");
    printf("Version: 1.0\n");
    printf("- Block outbound traffic for a process by PID:\n");
    printf("  silencer.exe block <PID>\n\n");
    printf("- Remove all WFP filters applied by this tool:\n");
    printf("  silencer.exe unblockall\n\n");
    printf("- Remove a specific WFP filter by filter id:\n");
    printf("  silencer.exe unblock <filter id>\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        PrintHelp();
        return 1;
    }

    if (strcasecmp(argv[1], "-h") == 0 || strcasecmp(argv[1], "--help") == 0) {
        PrintHelp();
        return 1;
    }
    
    if (!CheckProcessIntegrityLevel()) {
        return 1;
    }

    if (strcmp(argv[1], "block") == 0) {
        if (argc < 3) {
            printf("[-] Missing PID argument.\n");
            return 1;
        }
        DWORD pid = atoi(argv[2]);
        if (pid == 0) {
            printf("[-] Invalid PID.\n");
            return 1;
        }
        BlockProcessByPID(pid);
    } else if (strcmp(argv[1], "unblockall") == 0) {
        UnblockAllWfpFilters();
    } else if (strcmp(argv[1], "unblock") == 0) {
        if (argc < 3) {
            printf("[-] Missing filter id argument.\n");
            return 1;
        }
        char *endptr;
        errno = 0;
        UINT64 filterId = strtoull(argv[2], &endptr, 10);
        if (errno != 0 || endptr == argv[2]) {
            printf("[-] Invalid filter id.\n");
            return 1;
        }
        UnblockWfpFilter(filterId);
    } else {
        printf("[-] Invalid argument: \"%s\".\n", argv[1]);
        return 1;
    }
    return 0;
}