#pragma once

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>
#include <stdbool.h>

const int sPrimaryEccKeyIndex = 0x81008123;

int ErrorToTpmRc(int rc)
{
    const int sErrorFormatTypeMask = 0x80;
    const int sFormat0ErrorCodeMask = 0x97FU;
    const int sFormat1ErrorCodeMask = 0xBFU;

    bool isFormat1ErrorType = ((rc & sErrorFormatTypeMask) != 0);
    int errorCodeMask = (isFormat1ErrorType ? sFormat1ErrorCodeMask : sFormat0ErrorCodeMask);

    return rc & errorCodeMask;
}

int GetPrimaryECCKey(WOLFTPM2_DEV* pDev,
                     WOLFTPM2_KEY* key,
                     ecc_key* pWolfEccKey,
                     int tpmDevId,
                     TPMT_PUBLIC* publicTemplate)
{
    int rc = 0;

    // Try to load ECC key
    rc = wolfTPM2_ReadPublicKey(pDev, key, sPrimaryEccKeyIndex);

    // If it does not exist, create it
    if (ErrorToTpmRc(rc) == TPM_RC_HANDLE)
    {
        printf("No key was found at index 0x%x. Generating a new one.\n", sPrimaryEccKeyIndex);
        // Create primary key
        rc = wolfTPM2_CreatePrimaryKey(pDev, key, TPM_RH_OWNER, publicTemplate, NULL, 0);
        if (rc == TPM_RC_SUCCESS) {
            // Make key persistent
            rc = wolfTPM2_NVStoreKey(pDev, TPM_RH_OWNER, key, sPrimaryEccKeyIndex);
        }


    }

    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    printf("An existing key was found at index 0x%x.\n", sPrimaryEccKeyIndex);

    if (pWolfEccKey) {
        /* setup wolf ECC key with TPM deviceID, so crypto callbacks are used */
        rc = wc_ecc_init_ex((ecc_key*)pWolfEccKey, NULL, tpmDevId);
        if (rc != 0) return rc;

        /* load public portion of TPM key into wolf ECC key */
        rc = wolfTPM2_EccKey_TpmToWolf(pDev, key, (ecc_key*)pWolfEccKey);
    }

    return rc;
}
