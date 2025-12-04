![](static/static/img/ "")

# Welcome to OpenEFT 2!

![OpenEFT Logo](static/oeftlogo-blk.png "OpenEFT Logo")

OpenEFT 2 is a lightweight web application for converting physical fingerprint cards into digital EFT files for use with ATF's eForms application.

This new version of OpenEFT ("OpenEFT 2") is a completely new app from the original OpenEFT (which we'll call *OpenEFT Classic* moving forward) and uses the NIST Biometric Image Software (NBIS) to handle the conversion.

## Features

1.  **Upload**: Supports high-resolution scans of FD-258 cards.
2.  **Live Scan**: Supports Integrated Biometrics' line of ten-print scanners (At least the IB Kojak).
3.  **Crop & Rotate**: Built-in tool to manually rotate and crop the image to the card boundary.
4.  **Align & Segment**: Suggests default fingerprint locations based on standard card layout.
6.  **Interactive Editor**: Allows users to adjust bounding boxes for individual prints to ensure accuracy.
7.  **Data Entry**: Validates and collects required Type-2 demographic data (Name, DOB, SSN, etc.).
8.  **EFT Generation**: Uses compiled NBIS tools (`an2k`, `nfiq`, `opj_compress`) to generate compliant EFT files.
9.  **Multi-Type Support**: Allows users to pick from Type-14 ("ATF-compliant, *suggested*) prints and full Type-4 (rolled) prints. **Note**: we recommend using ATF-compliant prints.
10.  **Smart Compression**: Automatically ensures the final EFT file is under ATF's 12MB limit by adjusting compression ratios if needed.

## Prerequisites

- **Docker**: The application is containerized. Ensure Docker is installed on your machine.
- **Docker Hub**: You can pull this directly from [Docker Hub](https://hub.docker.com/repository/docker/robbstumpf/openeft2)

## Build & Run

### 1. Build the Docker Image
**Important:** You must run this command from the **root directory** of the repository.

```bash
docker build -t openeft2 .
```

*Or* you can **pull the Image directly from Docker Hub** (Recommended):

```bash
docker pull robbstumpf/openeft2:latest
```

![Pull OpenEFT 2 via Docker Hub](static/img/docker1.jpg "Pull OpenEFT 2 via Docker Hub")

*Note: The build process compiles NBIS tools from source and may take a few minutes.*

### 2. Run the Container

If compiled manually...

```bash
docker run -p 8080:8080 openeft2
```

If pulled from Docker Hub...

```bash
docker run -p 8080:8080 robbstumpf/openeft2
```
![Run Docker container](static/img/docker2.jpg "Run Docker container")

### 3. Access the Application
Open your browser and navigate to:
[http://localhost:8080](http://localhost:8080)

## Usage Guide


### **Upload Card**

![FD258 upload](static/img/2.jpg "FD258 upload")

Select your scanned FD-258 image (JPG/PNG).


### **Crop & Rotate**

![FD258 crop](static/img/3.jpg "FD258 crop")

- Use the **Rotate** buttons to orient the card upright.
- Drag a box around the actual card area (excluding scanner bed background).
- Click "Next"


### **Select Print Type**

![Select print type](static/img/4.jpg "Select print type")

- Select your desired print type. We recommend going with the ATF-complaint Type-14 records, as the rolled (Type 4) are not used by the ATF.


### **Verify Boxes**

![Verify bounding boxes](static/img/5.jpg "Verify bounding boxes")

You will see the aligned image with boxes around the expected fingerprint locations.
- **Drag** boxes to move them.
- **Resize** boxes using the corners (Top-Left or Bottom-Right).
- Ensure the boxes capture the full print.


### **Enter Data**

![Personal details](static/img/6.jpg "Personal details")

Fill out the required fields.


### **Verify Details**

![Verify details](static/img/7.jpg "Verify details")

Final confirmation is presented of your personal details and the fingerprint images

![Download EFT](static/img/8.jpg "Download EFT")


### **Download**

That's it, you're done! Click "Delete File & Start Over" to remove the temporary session data.



## Technical Details

-   **Backend**: FastAPI (Python)
-   **Image Processing**: OpenCV, NumPy
-   **Biometrics**: NBIS (NIST Biometric Image Software) - `opj_compress` (JPEG 2000), `nfseg`, `an2k`.
-   **Frontend**: Vanilla HTML/JS/CSS.

## Troubleshooting

**Build Fails with "setup.sh not found":**
Ensure you are running `docker build .` from the root of the project folder, not inside a subdirectory.
