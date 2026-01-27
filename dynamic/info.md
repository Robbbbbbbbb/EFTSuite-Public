---

# New EFT
This section will allow you to create a new EFT! Currently, it will only permit you to create an EFT with Type-14 records (Left Slap, Right Slap, and Thumbs), as the ATF requires a transaction type of FAUF for eForms. Per the EBTS specifications, EFTs with a TOT (Type of Transaction) flag of FAUF *only* uses Type-14 records. Type 4 records (rolled) are not used and are not necessary to include.

---

# Capture Prints
This function will allow OpenEFT 2 to interface with a physical fingerprint scanner and capture prints directly into the OEFT2 software. You *must* use the included helper application (which only supports Windows 10 and Windows 11 at this time) to bridge the scanner with OEFT2. This is due to a limitation with Chromium's native WebUSB API. You must also have the proper drivers for your scanner installed, which should be included for the supported devices below.

---

## Supported Devices
The following devices are known to work with OpenEFT 2:
* Integrated Biometrics Kojak
* Possibly other IB ten-print scanners that use the same SDK

> *Please note*: We will not be adding support for Identification International devices (like the i3), as the company was not willing to provide the SDK for integration. If you have access to the SDK and would like us to help with integration, please reach out.

---

# View/Edit EFT
## Read Only Mode
This mode will allow you to read an EFT's contents. It will display both the raw an2k output as well as the Type 2 (demographic) and Type-14 (print) records.
## Edit Mode
This mode is an "Advanced" mode that allows the user to edit the raw values of an EFT. There is NO logic checking in this step on purpose - that way, if there is something that OpenEFT 2 fails to do properly (like include the proper country code for a Place of Birth), it can be edited manually with that information. However, it also means that an EFT can be saved with invalid field values. **Use this function with caution**.

---

# Changelog

### v2.0.2

1. Type-14 print conversion is depreciated. Disabled the ability to create these.
2. Revised upload boxes to make uploading files easier.
3. Significantly improved print quality.
4. Added logic in place to check image PPI. If under required PPI, users are alerted that they must select a better quality image for upload.
5. JSON.parse issue should be fixed (cross your fingers!)
6. Fingerprint bounding box labels and aspect ratios are improved.
7. Live capture helper address is now configurable. This is in prep for the new Helper and Portaprint.
8. In some circumstances, live capture was presenting slaps in reverse orientation. Fixed.

### v2.0.1

OEFT2 is here! Aside from the complete rewrite, there are two improvements worth noting here:

1. TCN (transaction number) is shortened to appease the requirements of Silencer Central
2. Type 4 records are now createable to appease SilenecerShop (which requires Type 4 records for some reason). I recommend using Type 14 records (ATF-compliant) unless you explicitly need Type 4 records.
