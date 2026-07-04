// EFTHelper, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null
// IBscanUltimate.DLL
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace IBscanUltimate
{
	public class DLL
	{
		public enum IBSU_ImageFormat
		{
			IBSU_IMG_FORMAT_GRAY,
			IBSU_IMG_FORMAT_RGB24,
			IBSU_IMG_FORMAT_RGB32,
			IBSU_IMG_FORMAT_UNKNOWN
		}

		[StructLayout(LayoutKind.Explicit)]
		public struct IBSU_ImageData
		{
			[FieldOffset(0)]
			public IntPtr Buffer;

			[FieldOffset(8)]
			public uint Width;

			[FieldOffset(12)]
			public uint Height;

			[FieldOffset(16)]
			public double ResolutionX;

			[FieldOffset(24)]
			public double ResolutionY;

			[FieldOffset(32)]
			public double FrameTime;

			[FieldOffset(40)]
			public int Pitch;

			[FieldOffset(44)]
			public byte BitsPerPixel;

			[FieldOffset(48)]
			public IBSU_ImageFormat Format;

			[FieldOffset(52)]
			[MarshalAs(UnmanagedType.Bool)]
			public bool IsFinal;

			[FieldOffset(56)]
			public uint ProcessThres;
		}

		public delegate void IBSU_Callback(int deviceHandle, IntPtr pContext);

		public delegate void IBSU_CallbackPreviewImage(int deviceHandle, IntPtr pContext, IntPtr image);

		public delegate void IBSU_CallbackFingerCount(int deviceHandle, IntPtr pContext, IBSU_FingerCountState fingerCountState);

		public delegate void IBSU_CallbackFingerQuality(int deviceHandle, IntPtr pContext, IntPtr pQualityArray, int qualityArrayCount);

		public delegate void IBSU_CallbackDeviceCount(int detectedDevices, IntPtr pContext);

		public delegate void IBSU_CallbackInitProgress(int deviceIndex, IntPtr pContext, int progressValue);

		public delegate void IBSU_CallbackTakingAcquisition(int deviceHandle, IntPtr pContext, IBSU_ImageType imageType);

		public delegate void IBSU_CallbackCompleteAcquisition(int deviceHandle, IntPtr pContext, IBSU_ImageType imageType);

		public delegate void IBSU_CallbackResultImage(int deviceHandle, IntPtr pContext, IBSU_ImageData image, IBSU_ImageType imageType, IntPtr pSplitImageArray, int splitImageArrayCount);

		public delegate void IBSU_CallbackResultImageEx(int deviceHandle, IntPtr pContext, int imageStatus, IntPtr image, IBSU_ImageType imageType, int detectedFingerCount, int segmentImageArrayCount, IntPtr pSegmentImageArray, IntPtr SegmentPositionArray);

		public delegate void IBSU_CallbackClearPlatenAtCapture(int deviceHandle, IntPtr pContext, IBSU_PlatenState platenState);

		public delegate void IBSU_CallbackAsyncOpenDevice(int deviceIndex, IntPtr pContext, int deviceHandle, int errorCode);

		public delegate void IBSU_CallbackNotifyMessage(int deviceHandle, IntPtr pContext, int notifyMessage);

		public delegate void IBSU_CallbackKeyButtons(int deviceHandle, IntPtr pContext, int pressedKeyButtons);

		[StructLayout(LayoutKind.Explicit)]
		public struct IBSU_RECT
		{
			[FieldOffset(0)]
			public int left;

			[FieldOffset(4)]
			public int top;

			[FieldOffset(8)]
			public int right;

			[FieldOffset(12)]
			public int bottom;
		}

		public struct IBSU_SdkVersion
		{
			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
			public string Product;

			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
			public string File;
		}

		public struct IBSU_DeviceDesc
		{
			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
			public string serialNumber;

			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
			public string productName;

			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
			public string interfaceType;

			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
			public string fwVersion;

			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
			public string devRevision;

			public int handle;

			public bool IsHandleOpened;

			public bool IsDeviceLocked;

			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
			public string customerString;
		}

		[StructLayout(LayoutKind.Explicit)]
		public struct IBSU_SegmentPosition
		{
			[FieldOffset(0)]
			public short x1;

			[FieldOffset(2)]
			public short y1;

			[FieldOffset(4)]
			public short x2;

			[FieldOffset(6)]
			public short y2;

			[FieldOffset(8)]
			public short x3;

			[FieldOffset(10)]
			public short y3;

			[FieldOffset(12)]
			public short x4;

			[FieldOffset(14)]
			public short y4;
		}

		public enum IBSU_ImageType
		{
			ENUM_IBSU_TYPE_NONE,
			ENUM_IBSU_ROLL_SINGLE_FINGER,
			ENUM_IBSU_FLAT_SINGLE_FINGER,
			ENUM_IBSU_FLAT_TWO_FINGERS,
			ENUM_IBSU_FLAT_FOUR_FINGERS,
			ENUM_IBSU_FLAT_THREE_FINGERS,
			ENUM_IBSU_FLAT_SINGLE_WRITERS_PALM,
			ENUM_IBSU_FLAT_SINGLE_UPPER_PALM,
			ENUM_IBSU_FLAT_SINGLE_LOWER_PALM
		}

		public enum IBSU_ImageResolution
		{
			ENUM_IBSU_IMAGE_RESOLUTION_500 = 500,
			ENUM_IBSU_IMAGE_RESOLUTION_1000 = 1000
		}

		public enum IBSU_PropertyId
		{
			ENUM_IBSU_PROPERTY_PRODUCT_ID = 0,
			ENUM_IBSU_PROPERTY_SERIAL_NUMBER = 1,
			ENUM_IBSU_PROPERTY_VENDOR_ID = 2,
			ENUM_IBSU_PROPERTY_IBIA_VENDOR_ID = 3,
			ENUM_IBSU_PROPERTY_IBIA_VERSION = 4,
			ENUM_IBSU_PROPERTY_IBIA_DEVICE_ID = 5,
			ENUM_IBSU_PROPERTY_FIRMWARE = 6,
			ENUM_IBSU_PROPERTY_REVISION = 7,
			ENUM_IBSU_PROPERTY_PRODUCTION_DATE = 8,
			ENUM_IBSU_PROPERTY_SERVICE_DATE = 9,
			ENUM_IBSU_PROPERTY_IMAGE_WIDTH = 10,
			ENUM_IBSU_PROPERTY_IMAGE_HEIGHT = 11,
			ENUM_IBSU_PROPERTY_IGNORE_FINGER_TIME = 12,
			ENUM_IBSU_PROPERTY_RECOMMENDED_LEVEL = 13,
			ENUM_IBSU_PROPERTY_POLLINGTIME_TO_BGETIMAGE = 14,
			ENUM_IBSU_PROPERTY_ENABLE_POWER_SAVE_MODE = 15,
			ENUM_IBSU_PROPERTY_RETRY_WRONG_COMMUNICATION = 16,
			ENUM_IBSU_PROPERTY_CAPTURE_TIMEOUT = 17,
			ENUM_IBSU_PROPERTY_ROLL_MIN_WIDTH = 18,
			ENUM_IBSU_PROPERTY_ROLL_MODE = 19,
			ENUM_IBSU_PROPERTY_ROLL_LEVEL = 20,
			ENUM_IBSU_PROPERTY_CAPTURE_AREA_THRESHOLD = 21,
			ENUM_IBSU_PROPERTY_ENABLE_DECIMATION = 22,
			ENUM_IBSU_PROPERTY_ENABLE_CAPTURE_ON_RELEASE = 23,
			ENUM_IBSU_PROPERTY_DEVICE_INDEX = 24,
			ENUM_IBSU_PROPERTY_DEVICE_ID = 25,
			ENUM_IBSU_PROPERTY_SUPER_DRY_MODE = 26,
			ENUM_IBSU_PROPERTY_MIN_CAPTURE_TIME_IN_SUPER_DRY_MODE = 27,
			ENUM_IBSU_PROPERTY_ROLLED_IMAGE_WIDTH = 28,
			ENUM_IBSU_PROPERTY_ROLLED_IMAGE_HEIGHT = 29,
			ENUM_IBSU_PROPERTY_NO_PREVIEW_IMAGE = 30,
			ENUM_IBSU_PROPERTY_ROLL_IMAGE_OVERRIDE = 31,
			ENUM_IBSU_PROPERTY_WARNING_MESSAGE_INVALID_AREA = 32,
			ENUM_IBSU_PROPERTY_ENABLE_WET_FINGER_DETECT = 33,
			ENUM_IBSU_PROPERTY_WET_FINGER_DETECT_LEVEL = 34,
			ENUM_IBSU_PROPERTY_WET_FINGER_DETECT_LEVEL_THRESHOLD = 35,
			ENUM_IBSU_PROPERTY_START_POSITION_OF_ROLLING_AREA = 36,
			ENUM_IBSU_PROPERTY_START_ROLL_WITHOUT_LOCK = 37,
			ENUM_IBSU_PROPERTY_ENABLE_TOF = 38,
			ENUM_IBSU_PROPERTY_ENABLE_ENCRYPTION = 39,
			ENUM_IBSU_PROPERTY_IS_SPOOF_SUPPORTED = 40,
			ENUM_IBSU_PROPERTY_ENABLE_SPOOF = 41,
			ENUM_IBSU_PROPERTY_SPOOF_LEVEL = 42,
			ENUM_IBSU_PROPERTY_VIEW_ENCRYPTION_IMAGE_MODE = 43,
			ENUM_IBSU_PROPERTY_FINGERPRINT_SEGMENTATION_MODE = 44,
			ENUM_IBSU_PROPERTY_ROLL_METHOD = 45,
			ENUM_IBSU_PROPERTY_RENEWAL_OPPOSITE_IMGAE_LEVEL = 46,
			ENUM_IBSU_PROPERTY_PREVIEW_IMAGE_QUALITY_FOR_KOJAK = 47,
			ENUM_IBSU_PROPERTY_ADAPTIVE_CAPTURE_MODE = 48,
			ENUM_IBSU_PROPERTY_ENABLE_KOJAK_BEHAVIOR_2_6 = 49,
			ENUM_IBSU_PROPERTY_DISABLE_SEGMENT_ROTATION = 50,
			ENUM_IBSU_PROPERTY_DR_MODE_ZOOM_IN = 51,
			ENUM_IBSU_PROPERTY_RESERVED_1 = 200,
			ENUM_IBSU_PROPERTY_RESERVED_2 = 201,
			ENUM_IBSU_PROPERTY_RESERVED_100 = 202,
			ENUM_IBSU_PROPERTY_RESERVED_IMAGE_PROCESS_THRESHOLD = 400,
			ENUM_IBSU_PROPERTY_RESERVED_ENABLE_TOF_FOR_ROLL = 401,
			ENUM_IBSU_PROPERTY_RESERVED_CAPTURE_BRIGHTNESS_THRESHOLD_FOR_FLAT = 402,
			ENUM_IBSU_PROPERTY_RESERVED_CAPTURE_BRIGHTNESS_THRESHOLD_FOR_ROLL = 403,
			ENUM_IBSU_PROPERTY_RESERVED_ENHANCED_RESULT_IMAGE = 404,
			ENUM_IBSU_PROPERTY_RESERVED_ENHANCED_RESULT_IMAGE_LEVEL = 405,
			ENUM_IBSU_PROPERTY_RESERVED_ENABLE_SLIP_DETECTION = 406,
			ENUM_IBSU_PROPERTY_RESERVED_SLIP_DETECTION_LEVEL = 407,
			ENUM_IBSU_PROPERTY_RESERVED_ENABLE_TRICK_CAPTURE = 408
		}

		public enum IBSU_ClientWindowPropertyId
		{
			ENUM_IBSU_WINDOW_PROPERTY_BK_COLOR,
			ENUM_IBSU_WINDOW_PROPERTY_ROLL_GUIDE_LINE,
			ENUM_IBSU_WINDOW_PROPERTY_DISP_INVALID_AREA,
			ENUM_IBSU_WINDOW_PROPERTY_SCALE_FACTOR,
			ENUM_IBSU_WINDOW_PROPERTY_LEFT_MARGIN,
			ENUM_IBSU_WINDOW_PROPERTY_TOP_MARGIN,
			ENUM_IBSU_WINDOW_PROPERTY_ROLL_GUIDE_LINE_WIDTH,
			ENUM_IBSU_WINDOW_PROPERTY_SCALE_FACTOR_EX,
			ENUM_IBSU_WINDOW_PROPERTY_KEEP_REDRAW_LAST_IMAGE,
			ENUM_IBSU_WINDOW_PROPERTY_ROLL_GUIDE_LINE_COLOR
		}

		public enum IBSU_FingerCountState
		{
			ENUM_IBSU_FINGER_COUNT_OK,
			ENUM_IBSU_TOO_MANY_FINGERS,
			ENUM_IBSU_TOO_FEW_FINGERS,
			ENUM_IBSU_NON_FINGER
		}

		public enum IBSU_FingerQualityState
		{
			ENUM_IBSU_FINGER_NOT_PRESENT,
			ENUM_IBSU_QUALITY_GOOD,
			ENUM_IBSU_QUALITY_FAIR,
			ENUM_IBSU_QUALITY_POOR,
			ENUM_IBSU_QUALITY_INVALID_AREA_TOP,
			ENUM_IBSU_QUALITY_INVALID_AREA_LEFT,
			ENUM_IBSU_QUALITY_INVALID_AREA_RIGHT,
			ENUM_IBSU_QUALITY_INVALID_AREA_BOTTOM
		}

		public enum IBSU_LEOperationMode
		{
			ENUM_IBSU_LE_OPERATION_AUTO,
			ENUM_IBSU_LE_OPERATION_ON,
			ENUM_IBSU_LE_OPERATION_OFF
		}

		public enum IBSU_PlatenState
		{
			ENUM_IBSU_PLATEN_CLEARD,
			ENUM_IBSU_PLATEN_HAS_FINGERS
		}

		public enum IBSU_Events
		{
			ENUM_IBSU_ESSENTIAL_EVENT_DEVICE_COUNT,
			ENUM_IBSU_ESSENTIAL_EVENT_COMMUNICATION_BREAK,
			ENUM_IBSU_ESSENTIAL_EVENT_PREVIEW_IMAGE,
			ENUM_IBSU_ESSENTIAL_EVENT_TAKING_ACQUISITION,
			ENUM_IBSU_ESSENTIAL_EVENT_COMPLETE_ACQUISITION,
			ENUM_IBSU_ESSENTIAL_EVENT_RESULT_IMAGE,
			ENUM_IBSU_OPTIONAL_EVENT_FINGER_QUALITY,
			ENUM_IBSU_OPTIONAL_EVENT_FINGER_COUNT,
			ENUM_IBSU_ESSENTIAL_EVENT_INIT_PROGRESS,
			ENUM_IBSU_OPTIONAL_EVENT_CLEAR_PLATEN_AT_CAPTURE,
			ENUM_IBSU_ESSENTIAL_EVENT_ASYNC_OPEN_DEVICE,
			ENUM_IBSU_OPTIONAL_EVENT_NOTIFY_MESSAGE,
			ENUM_IBSU_ESSENTIAL_EVENT_RESULT_IMAGE_EX,
			ENUM_IBSU_ESSENTIAL_EVENT_KEYBUTTON
		}

		public enum IBSU_LedType
		{
			ENUM_IBSU_LED_TYPE_NONE,
			ENUM_IBSU_LED_TYPE_TSCAN,
			ENUM_IBSU_LED_TYPE_FSCAN
		}

		public enum IBSU_RollingState
		{
			ENUM_IBSU_ROLLING_NOT_PRESENT,
			ENUM_IBSU_ROLLING_TAKE_ACQUISITION,
			ENUM_IBSU_ROLLING_COMPLETE_ACQUISITION,
			ENUM_IBSU_ROLLING_RESULT_IMAGE
		}

		public enum IBSU_OverlayShapePattern
		{
			ENUM_IBSU_OVERLAY_SHAPE_RECTANGLE,
			ENUM_IBSU_OVERLAY_SHAPE_ELLIPSE,
			ENUM_IBSU_OVERLAY_SHAPE_CROSS,
			ENUM_IBSU_OVERLAY_SHAPE_ARROW
		}

		public enum IBSU_BeeperType
		{
			ENUM_IBSU_BEEPER_TYPE_NONE,
			ENUM_IBSU_BEEPER_TYPE_MONOTONE
		}

		public enum IBSU_BeepPattern
		{
			ENUM_IBSU_BEEP_PATTERN_GENERIC,
			ENUM_IBSU_BEEP_PATTERN_REPEAT
		}

		public enum IBSU_EncryptionMode
		{
			ENUM_IBSU_ENCRYPTION_KEY_RANDOM,
			ENUM_IBSU_ENCRYPTION_KEY_CUSTOM
		}

		public enum IBSU_CombineImageWhichHand
		{
			ENUM_IBSU_COMBINE_IMAGE_LEFT_HAND,
			ENUM_IBSU_COMBINE_IMAGE_RIGHT_HAND
		}

		public enum IBSU_HashType
		{
			ENUM_IBSU_HASH_TYPE_SHA256,
			ENUM_IBSU_HASH_TYPE_RESERVED
		}

		public enum IBSM_ImageFormat
		{
			IBSM_IMG_FORMAT_NO_BIT_PACKING,
			IBSM_IMG_FORMAT_BIT_PACKED,
			IBSM_IMG_FORMAT_WSQ,
			IBSM_IMG_FORMAT_JPEG_LOSSY,
			IBSM_IMG_FORMAT_JPEG2000_LOSSY,
			IBSM_IMG_FORMAT_JPEG2000_LOSSLESS,
			IBSM_IMG_FORMAT_PNG,
			IBSM_IMG_FORMAT_UNKNOWN
		}

		public enum IBSM_ImpressionType
		{
			IBSM_IMPRESSION_TYPE_LIVE_SCAN_PLAIN = 0,
			IBSM_IMPRESSION_TYPE_LIVE_SCAN_ROLLED = 1,
			IBSM_IMPRESSION_TYPE_NONLIVE_SCAN_PLAIN = 2,
			IBSM_IMPRESSION_TYPE_NONLIVE_SCAN_ROLLED = 3,
			IBSM_IMPRESSION_TYPE_LATENT_IMPRESSION = 4,
			IBSM_IMPRESSION_TYPE_LATENT_TRACING = 5,
			IBSM_IMPRESSION_TYPE_LATENT_PHOTO = 6,
			IBSM_IMPRESSION_TYPE_LATENT_LIFT = 7,
			IBSM_IMPRESSION_TYPE_LIVE_SCAN_SWIPE = 8,
			IBSM_IMPRESSION_TYPE_LIVE_SCAN_VERTICAL_ROLL = 9,
			IBSM_IMPRESSION_TYPE_LIVE_SCAN_PALM = 10,
			IBSM_IMPRESSION_TYPE_NONLIVE_SCAN_PALM = 11,
			IBSM_IMPRESSION_TYPE_LATENT_PALM_IMPRESSION = 12,
			IBSM_IMPRESSION_TYPE_LATENT_PALM_TRACING = 13,
			IBSM_IMPRESSION_TYPE_LATENT_PALM_PHOTO = 14,
			IBSM_IMPRESSION_TYPE_LATENT_PALM_LIFT = 15,
			IBSM_IMPRESSION_TYPE_LIVE_SCAN_OPTICAL_CONTRCTLESS_PLAIN = 24,
			IBSM_IMPRESSION_TYPE_OTHER = 28,
			IBSM_IMPRESSION_TYPE_UNKNOWN = 29
		}

		public enum IBSM_FingerPosition
		{
			IBSM_FINGER_POSITION_UNKNOWN = 0,
			IBSM_FINGER_POSITION_RIGHT_THUMB = 1,
			IBSM_FINGER_POSITION_RIGHT_INDEX_FINGER = 2,
			IBSM_FINGER_POSITION_RIGHT_MIDDLE_FINGER = 3,
			IBSM_FINGER_POSITION_RIGHT_RING_FINGER = 4,
			IBSM_FINGER_POSITION_RIGHT_LITTLE_FINGER = 5,
			IBSM_FINGER_POSITION_LEFT_THUMB = 6,
			IBSM_FINGER_POSITION_LEFT_INDEX_FINGER = 7,
			IBSM_FINGER_POSITION_LEFT_MIDDLE_FINGER = 8,
			IBSM_FINGER_POSITION_LEFT_RING_FINGER = 9,
			IBSM_FINGER_POSITION_LEFT_LITTLE_FINGER = 10,
			IBSM_FINGER_POSITION_PLAIN_RIGHT_FOUR_FINGERS = 13,
			IBSM_FINGER_POSITION_PLAIN_LEFT_FOUR_FINGERS = 14,
			IBSM_FINGER_POSITION_PLAIN_THUMBS = 15,
			IBSM_FINGER_POSITION_UNKNOWN_PALM = 20,
			IBSM_FINGER_POSITION_RIGHT_FULL_PALM = 21,
			IBSM_FINGER_POSITION_RIGHT_WRITERS_PALM = 22,
			IBSM_FINGER_POSITION_LEFT_FULL_PALM = 23,
			IBSM_FINGER_POSITION_LEFT_WRITERS_PALM = 24,
			IBSM_FINGER_POSITION_RIGHT_LOWER_PALM = 25,
			IBSM_FINGER_POSITION_RIGHT_UPPER_PALM = 26,
			IBSM_FINGER_POSITION_LEFT_LOWER_PALM = 27,
			IBSM_FINGER_POSITION_LEFT_UPPER_PALM = 28,
			IBSM_FINGER_POSITION_RIGHT_OTHER = 29,
			IBSM_FINGER_POSITION_LEFT_OTHER = 30,
			IBSM_FINGER_POSITION_RIGHT_INTERDIGITAL = 31,
			IBSM_FINGER_POSITION_RIGHT_THENAR = 32,
			IBSM_FINGER_POSITION_RIGHT_HYPOTHENAR = 33,
			IBSM_FINGER_POSITION_LEFT_INTERDIGITAL = 34,
			IBSM_FINGER_POSITION_LEFT_THENAR = 35,
			IBSM_FINGER_POSITION_LEFT_HYPOTHENAR = 36,
			IBSM_FINGER_POSITION_RIGHT_INDEX_AND_MIDDLE = 40,
			IBSM_FINGER_POSITION_RIGHT_MIDDLE_AND_RING = 41,
			IBSM_FINGER_POSITION_RIGHT_RING_AND_LITTLE = 42,
			IBSM_FINGER_POSITION_LEFT_INDEX_AND_MIDDLE = 43,
			IBSM_FINGER_POSITION_LEFT_MIDDLE_AND_RING = 44,
			IBSM_FINGER_POSITION_LEFT_RING_AND_LITTLE = 45,
			IBSM_FINGER_POSITION_RIGHT_INDEX_AND_LEFT_INDEX = 46,
			IBSM_FINGER_POSITION_RIGHT_INDEX_AND_MIDDLE_AND_RING = 47,
			IBSM_FINGER_POSITION_RIGHT_MIDDLE_AND_RING_AND_LITTLE = 48,
			IBSM_FINGER_POSITION_LEFT_INDEX_AND_MIDDLE_AND_RING = 49,
			IBSM_FINGER_POSITION_LEFT_MIDDLE_AND_RING_AND_LITTLE = 50,
			IBSM_FINGER_POSITION_UNKNOWN_HALF_PALM = 51,
			IBSM_FINGER_POSITION_RIGHT_HALF_PALM = 52,
			IBSM_FINGER_POSITION_LEFT_HALF_PALM = 53,
			IBSM_FINGER_POSITION_RIGHT_LOWER_HALF_PALM = 54,
			IBSM_FINGER_POSITION_RIGHT_UPPER_HALF_PALM = 55,
			IBSM_FINGER_POSITION_LEFT_LOWER_HALF_PALM = 56,
			IBSM_FINGER_POSITION_LEFT_UPPER_HALF_PALM = 57,
			IBSM_FINGER_POSITION_LEFT_CENTER_JOINT = 58,
			IBSM_FINGER_POSITION_RIGHT_CENTER_JOINT = 59,
			IBSM_FINGER_POSITION_LEFT_SIDE_JOINT = 60,
			IBSM_FINGER_POSITION_RIGHT_SIDE_JOINT = 61,
			IBSM_FINGER_POSITION_LEFT_ROLL_JOINT = 62,
			IBSM_FINGER_POSITION_RIGHT_ROLL_JOINT = 63,
			IBSM_FINGER_POSITION_LEFT_ROLL_UP = 64,
			IBSM_FINGER_POSITION_RIGHT_ROLL_UP = 65
		}

		public enum IBSM_CaptureDeviceTechID
		{
			IBSM_CAPTURE_DEVICE_UNKNOWN_OR_UNSPECIFIED,
			IBSM_CAPTURE_DEVICE_WHITE_LIGHT_OPTICAL_TIR,
			IBSM_CAPTURE_DEVICE_WHITE_LIGHT_OPTICAL_DIRECT_VIEW_ON_PLATEN,
			IBSM_CAPTURE_DEVICE_WHITE_LIGHT_OPTICAL_TOUCHLESS,
			IBSM_CAPTURE_DEVICE_MONOCHROMATIC_VISIBLE_OPTICAL_TIR,
			IBSM_CAPTURE_DEVICE_MONOCHROMATIC_VISIBLE_OPTICAL_DIRECT_VIEW_ON_PLATEN,
			IBSM_CAPTURE_DEVICE_MONOCHROMATIC_VISIBLE_OPTICAL_TOUCHLESS,
			IBSM_CAPTURE_DEVICE_MONOCHROMATIC_IR_OPTICAL_TIR,
			IBSM_CAPTURE_DEVICE_MONOCHROMATIC_IR_OPTICAL_DIRECT_VIEW_ON_PLATEN,
			IBSM_CAPTURE_DEVICE_MONOCHROMATIC_IR_OPTICAL_TOUCHLESS,
			IBSM_CAPTURE_DEVICE_MULTISPECTRAL_OPTICAL_TIR,
			IBSM_CAPTURE_DEVICE_MULTISPECTRAL_OPTICAL_DIRECT_VIEW_ON_PLATEN,
			IBSM_CAPTURE_DEVICE_MULTISPECTRAL_OPTICAL_TOUCHLESS,
			IBSM_CAPTURE_DEVICE_ELECTRO_LUMINESCENT,
			IBSM_CAPTURE_DEVICE_SEMICONDUCTOR_CAPACITIVE,
			IBSM_CAPTURE_DEVICE_SEMICONDUCTOR_RF,
			IBSM_CAPTURE_DEVICE_SEMICONDUCTOR_THEMAL,
			IBSM_CAPTURE_DEVICE_PRESSURE_SENSITIVE,
			IBSM_CAPTURE_DEVICE_ULTRASOUND,
			IBSM_CAPTURE_DEVICE_MECHANICAL,
			IBSM_CAPTURE_DEVICE_GLASS_FIBER
		}

		public enum IBSM_CaptureDeviceTypeID
		{
			IBSM_CAPTURE_DEVICE_TYPE_ID_UNKNOWN = 0,
			IBSM_CAPTURE_DEVICE_TYPE_ID_CURVE = 4100,
			IBSM_CAPTURE_DEVICE_TYPE_ID_WATSON = 4101,
			IBSM_CAPTURE_DEVICE_TYPE_ID_SHERLOCK = 4112,
			IBSM_CAPTURE_DEVICE_TYPE_ID_WATSON_MINI = 4128,
			IBSM_CAPTURE_DEVICE_TYPE_ID_COLUMBO = 4352,
			IBSM_CAPTURE_DEVICE_TYPE_ID_HOLMES = 4608,
			IBSM_CAPTURE_DEVICE_TYPE_ID_KOJAK = 4864,
			IBSM_CAPTURE_DEVICE_TYPE_ID_FIVE0 = 5376
		}

		public enum IBSM_CaptureDeviceVendorID
		{
			IBSM_CAPTURE_DEVICE_VENDOR_ID_UNREPORTED = 0,
			IBSM_CAPTURE_DEVICE_VENDOR_INTEGRATED_BIOMETRICS = 4415
		}

		public struct IBSM_ImageData
		{
			public IBSM_ImageFormat ImageFormat;
			public IBSM_ImpressionType ImpressionType;
			public IBSM_FingerPosition FingerPosition;
			public IBSM_CaptureDeviceTechID CaptureDeviceTechID;
			public ushort CaptureDeviceVendorID;
			public ushort CaptureDeviceTypeID;
			public ushort ScanSamplingX;
			public ushort ScanSamplingY;
			public ushort ImageSamplingX;
			public ushort ImageSamplingY;
			public ushort ImageSizeX;
			public ushort ImageSizeY;
			public byte ScaleUnit;
			public byte BitDepth;
			public uint ImageDataLength;
			public IntPtr ImageData;
		}

		public enum IBSM_TemplateVersion
		{
			IBSM_TEMPLATE_VERSION_IBISDK_0 = 0,
			IBSM_TEMPLATE_VERSION_IBISDK_1 = 1,
			IBSM_TEMPLATE_VERSION_IBISDK_2 = 2,
			IBSM_TEMPLATE_VERSION_IBISDK_3 = 3,
			IBSM_TEMPLATE_VERSION_NEW_0 = 16
		}

		public struct IBSM_Template
		{
			private IBSM_TemplateVersion Version;
			private uint FingerPosition;
			private IBSM_ImpressionType ImpressionType;
			private IBSM_CaptureDeviceTechID CaptureDeviceTechID;
			private ushort CaptureDeviceVendorID;
			private ushort CaptureDeviceTypeID;
			private ushort ImageSamplingX;
			private ushort ImageSamplingY;
			private ushort ImageSizeX;
			private ushort ImageSizeY;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 257)]
			private uint[] Minutiae;

			private uint Reserved;
		}

		public enum IBSM_StandardFormat
		{
			ENUM_IBSM_STANDARD_FORMAT_ISO_19794_2_2005,
			ENUM_IBSM_STANDARD_FORMAT_ISO_19794_4_2005,
			ENUM_IBSM_STANDARD_FORMAT_ISO_19794_2_2011,
			ENUM_IBSM_STANDARD_FORMAT_ISO_19794_4_2011,
			ENUM_IBSM_STANDARD_FORMAT_ANSI_INCITS_378_2004,
			ENUM_IBSM_STANDARD_FORMAT_ANSI_INCITS_381_2004
		}

		public struct IBSM_StandardFormatData
		{
			public IntPtr Data;
			public uint DataLength;
			public IBSM_StandardFormat Format;
		}

		public const int IBSU_MAX_STR_LEN = 128;
		public const int IBSU_MIN_CONTRAST_VALUE = 0;
		public const int IBSU_MAX_CONTRAST_VALUE = 34;
		public const int IBSU_MAX_SEGMENT_COUNT = 5;
		public const int IBSU_BMP_GRAY_HEADER_LEN = 1078;
		public const int IBSU_BMP_RGB24_HEADER_LEN = 54;
		public const int IBSU_BMP_RGB32_HEADER_LEN = 54;
		public const int IBSU_OPTION_AUTO_CONTRAST = 1;
		public const int IBSU_OPTION_AUTO_CAPTURE = 2;
		public const int IBSU_OPTION_IGNORE_FINGER_COUNT = 4;
		public const uint IBSU_LED_NONE = 0u;
		public const uint IBSU_LED_ALL = uint.MaxValue;
		public const uint IBSU_LED_INIT_BLUE = 1u;
		public const uint IBSU_LED_SCAN_GREEN = 2u;
		public const uint IBSU_LED_SCAN_CURVE_RED = 16u;
		public const uint IBSU_LED_SCAN_CURVE_GREEN = 32u;
		public const uint IBSU_LED_SCAN_CURVE_BLUE = 64u;
		public const uint IBSU_LED_F_BLINK_GREEN = 268435456u;
		public const uint IBSU_LED_F_BLINK_RED = 536870912u;
		public const uint IBSU_LED_F_LEFT_LITTLE_GREEN = 16777216u;
		public const uint IBSU_LED_F_LEFT_LITTLE_RED = 33554432u;
		public const uint IBSU_LED_F_LEFT_RING_GREEN = 67108864u;
		public const uint IBSU_LED_F_LEFT_RING_RED = 134217728u;
		public const uint IBSU_LED_F_LEFT_MIDDLE_GREEN = 1048576u;
		public const uint IBSU_LED_F_LEFT_MIDDLE_RED = 2097152u;
		public const uint IBSU_LED_F_LEFT_INDEX_GREEN = 4194304u;
		public const uint IBSU_LED_F_LEFT_INDEX_RED = 8388608u;
		public const uint IBSU_LED_F_LEFT_THUMB_GREEN = 65536u;
		public const uint IBSU_LED_F_LEFT_THUMB_RED = 131072u;
		public const uint IBSU_LED_F_RIGHT_THUMB_GREEN = 262144u;
		public const uint IBSU_LED_F_RIGHT_THUMB_RED = 524288u;
		public const uint IBSU_LED_F_RIGHT_INDEX_GREEN = 4096u;
		public const uint IBSU_LED_F_RIGHT_INDEX_RED = 8192u;
		public const uint IBSU_LED_F_RIGHT_MIDDLE_GREEN = 16384u;
		public const uint IBSU_LED_F_RIGHT_MIDDLE_RED = 1073741824u;
		public const uint IBSU_LED_F_RIGHT_RING_GREEN = 256u;
		public const uint IBSU_LED_F_RIGHT_RING_RED = 512u;
		public const uint IBSU_LED_F_RIGHT_LITTLE_GREEN = 1024u;
		public const uint IBSU_LED_F_RIGHT_LITTLE_RED = 2048u;
		public const uint IBSU_LED_F_PROGRESS_ROLL = 16u;
		public const uint IBSU_LED_F_PROGRESS_LEFT_HAND = 32u;
		public const uint IBSU_LED_F_PROGRESS_TWO_THUMB = 64u;
		public const uint IBSU_LED_F_PROGRESS_RIGHT_HAND = 128u;
		public const uint IBSU_FINGER_NONE = 0u;
		public const uint IBSU_FINGER_LEFT_LITTLE = 1u;
		public const uint IBSU_FINGER_LEFT_RING = 2u;
		public const uint IBSU_FINGER_LEFT_MIDDLE = 4u;
		public const uint IBSU_FINGER_LEFT_INDEX = 8u;
		public const uint IBSU_FINGER_LEFT_THUMB = 16u;
		public const uint IBSU_FINGER_RIGHT_THUMB = 32u;
		public const uint IBSU_FINGER_RIGHT_INDEX = 64u;
		public const uint IBSU_FINGER_RIGHT_MIDDLE = 128u;
		public const uint IBSU_FINGER_RIGHT_RING = 256u;
		public const uint IBSU_FINGER_RIGHT_LITTLE = 512u;
		public const uint IBSU_FINGER_LEFT_HAND = 15u;
		public const uint IBSU_FINGER_RIGHT_HAND = 960u;
		public const uint IBSU_FINGER_BOTH_THUMBS = 48u;
		public const uint IBSU_FINGER_ALL = 1023u;
		public const uint IBSU_FINGER_LEFT_LITTLE_RING = 3u;
		public const uint IBSU_FINGER_LEFT_MIDDLE_INDEX = 12u;
		public const uint IBSU_FINGER_RIGHT_INDEX_MIDDLE = 192u;
		public const uint IBSU_FINGER_RIGHT_RING_LITTLE = 768u;
		public const int IBSU_MAX_MINUTIAE_SIZE = 257;
		public const int IBSU_STATUS_OK = 0;
		public const int IBSU_ERR_INVALID_PARAM_VALUE = -1;
		public const int IBSU_ERR_MEM_ALLOC = -2;
		public const int IBSU_ERR_NOT_SUPPORTED = -3;
		public const int IBSU_ERR_FILE_OPEN = -4;
		public const int IBSU_ERR_FILE_READ = -5;
		public const int IBSU_ERR_RESOURCE_LOCKED = -6;
		public const int IBSU_ERR_MISSING_RESOURCE = -7;
		public const int IBSU_ERR_INVALID_ACCESS_POINTER = -8;
		public const int IBSU_ERR_THREAD_CREATE = -9;
		public const int IBSU_ERR_COMMAND_FAILED = -10;
		public const int IBSU_ERR_LIBRARY_UNLOAD_FAILED = -11;
		public const int IBSU_ERR_CHANNEL_IO_COMMAND_FAILED = -100;
		public const int IBSU_ERR_CHANNEL_IO_READ_FAILED = -101;
		public const int IBSU_ERR_CHANNEL_IO_WRITE_FAILED = -102;
		public const int IBSU_ERR_CHANNEL_IO_READ_TIMEOUT = -103;
		public const int IBSU_ERR_CHANNEL_IO_WRITE_TIMEOUT = -104;
		public const int IBSU_ERR_CHANNEL_IO_UNEXPECTED_FAILED = -105;
		public const int IBSU_ERR_CHANNEL_IO_INVALID_HANDLE = -106;
		public const int IBSU_ERR_CHANNEL_IO_WRONG_PIPE_INDEX = -107;
		public const int IBSU_ERR_DEVICE_IO = -200;
		public const int IBSU_ERR_DEVICE_NOT_FOUND = -201;
		public const int IBSU_ERR_DEVICE_NOT_MATCHED = -202;
		public const int IBSU_ERR_DEVICE_ACTIVE = -203;
		public const int IBSU_ERR_DEVICE_NOT_INITIALIZED = -204;
		public const int IBSU_ERR_DEVICE_INVALID_STATE = -205;
		public const int IBSU_ERR_DEVICE_BUSY = -206;
		public const int IBSU_ERR_DEVICE_NOT_SUPPORTED_FEATURE = -207;
		public const int IBSU_ERR_INVALID_LICENSE = -208;
		public const int IBSU_ERR_USB20_REQUIRED = -209;
		public const int IBSU_ERR_DEVICE_ENABLED_POWER_SAVE_MODE = -210;
		public const int IBSU_ERR_DEVICE_NEED_UPDATE_FIRMWARE = -211;
		public const int IBSU_ERR_DEVICE_NEED_CALIBRATE_TOF = -212;
		public const int IBSU_ERR_DEVICE_INVALID_CALIBRATION_DATA = -213;
		public const int IBSU_ERR_DEVICE_HIGHER_SDK_REQUIRED = -214;
		public const int IBSU_ERR_DEVICE_LOCK_INVALID_BUFF = -215;
		public const int IBSU_ERR_DEVICE_LOCK_INFO_EMPTY = -216;
		public const int IBSU_ERR_DEVICE_LOCK_INFO_NOT_MATCHED = -217;
		public const int IBSU_ERR_DEVICE_LOCK_INVALID_CHECKSUM = -218;
		public const int IBSU_ERR_DEVICE_LOCK_INVALID_KEY = -219;
		public const int IBSU_ERR_DEVICE_LOCK_LOCKED = -220;
		public const int IBSU_ERR_DEVICE_LOCK_ILLEGAL_DEVICE = -221;
		public const int IBSU_ERR_DEVICE_LOCK_INVALID_SERIAL_FORMAT = -222;
		public const int IBSU_ERR_CAPTURE_COMMAND_FAILED = -300;
		public const int IBSU_ERR_CAPTURE_STOP = -301;
		public const int IBSU_ERR_CAPTURE_TIMEOUT = -302;
		public const int IBSU_ERR_CAPTURE_STILL_RUNNING = -303;
		public const int IBSU_ERR_CAPTURE_NOT_RUNNING = -304;
		public const int IBSU_ERR_CAPTURE_INVALID_MODE = -305;
		public const int IBSU_ERR_CAPTURE_ALGORITHM = -306;
		public const int IBSU_ERR_CAPTURE_ROLLING = -307;
		public const int IBSU_ERR_CAPTURE_ROLLING_TIMEOUT = -308;
		public const int IBSU_ERR_CLIENT_WINDOW = -400;
		public const int IBSU_ERR_CLIENT_WINDOW_NOT_CREATE = -401;
		public const int IBSU_ERR_INVALID_OVERLAY_HANDLE = -402;
		public const int IBSU_ERR_NBIS_NFIQ_FAILED = -500;
		public const int IBSU_ERR_NBIS_WSQ_ENCODE_FAILED = -501;
		public const int IBSU_ERR_NBIS_WSQ_DECODE_FAILED = -502;
		public const int IBSU_ERR_NBIS_PNG_ENCODE_FAILED = -503;
		public const int IBSU_ERR_NBIS_JP2_ENCODE_FAILED = -504;
		public const int IBSU_ERR_DUPLICATE_EXTRACTION_FAILED = -600;
		public const int IBSU_ERR_DUPLICATE_ALREADY_USED = -601;
		public const int IBSU_ERR_DUPLICATE_SEGMENTATION_FAILED = -602;
		public const int IBSU_ERR_DUPLICATE_MATCHING_FAILED = -603;
		public const int IBSU_WRN_CHANNEL_IO_FRAME_MISSING = 100;
		public const int IBSU_WRN_CHANNEL_IO_CAMERA_WRONG = 101;
		public const int IBSU_WRN_CHANNEL_IO_SLEEP_STATUS = 102;
		public const int IBSU_WRN_OUTDATED_FIRMWARE = 200;
		public const int IBSU_WRN_ALREADY_INITIALIZED = 201;
		public const int IBSU_WRN_API_DEPRECATED = 202;
		public const int IBSU_WRN_ALREADY_ENHANCED_IMAGE = 203;
		public const int IBSU_WRN_BGET_IMAGE = 300;
		public const int IBSU_WRN_ROLLING_NOT_RUNNING = 301;
		public const int IBSU_WRN_NO_FINGER = 302;
		public const int IBSU_WRN_INCORRECT_FINGERS = 303;
		public const int IBSU_WRN_ROLLING_SMEAR = 304;
		public const int IBSU_WRN_EMPTY_IBSM_RESULT_IMAGE = 400;
		public const int IBSU_WRN_QUALITY_INVALID_AREA = 512;
		public const int IBSU_WRN_INVALID_BRIGHTNESS_FINGERS = 600;
		public const int IBSU_WRN_WET_FINGERS = 601;
		public const int IBSU_WRN_MULTIPLE_FINGERS_DURING_ROLL = 602;
		public const int IBSU_WRN_SPOOF_DETECTED = 603;
		public const int IBSU_WRN_ROLLING_SLIP_DETECTED = 604;
		public const int IBSU_WRN_SPOOF_INIT_FAILED = 605;
		public const int IBSU_WRN_ROLLING_SHIFTED_HORIZONTALLY = 305;
		public const int IBSU_WRN_ROLLING_SHIFTED_VERTICALLY = 306;
		public const int IBSU_WRN_QUALITY_INVALID_AREA_HORIZONTALLY = 513;
		public const int IBSU_WRN_QUALITY_INVALID_AREA_VERTICALLY = 514;

		[DllImport("IBScanUltimate.DLL")]
		private static extern int IBSU_GetSDKVersion(ref IBSU_SdkVersion pVerinfo);

		public static int _IBSU_GetSDKVersion(ref IBSU_SdkVersion pVerinfo)
		{
			try { return IBSU_GetSDKVersion(ref pVerinfo); }
			catch { return -1; }
		}

		[DllImport("IBScanUltimate.DLL")]
		private static extern int IBSU_GetDeviceCount(ref int pDeviceCount);

		public static int _IBSU_GetDeviceCount(ref int pDeviceCount)
		{
			try { return IBSU_GetDeviceCount(ref pDeviceCount); }
			catch { return -1; }
		}

		[DllImport("IBScanUltimate.DLL")]
		private static extern int IBSU_OpenDevice(int deviceIndex, ref int handle);

		public static int _IBSU_OpenDevice(int deviceIndex, ref int handle)
		{
			try { return IBSU_OpenDevice(deviceIndex, ref handle); }
			catch { return -1; }
		}

		[DllImport("IBScanUltimate.DLL")]
		private static extern int IBSU_CloseDevice(int handle);

		public static int _IBSU_CloseDevice(int handle)
		{
			try { return IBSU_CloseDevice(handle); }
			catch { return -1; }
		}

		[DllImport("IBScanUltimate.DLL")]
		private static extern int IBSU_RegisterCallbacks(int handle, IBSU_Events events, Delegate pEventName, IntPtr pContext);

		public static int _IBSU_RegisterCallbacks(int handle, IBSU_Events events, Delegate pEventName, IntPtr pContext)
		{
			try { return IBSU_RegisterCallbacks(handle, events, pEventName, pContext); }
			catch { return -1; }
		}

		[DllImport("IBScanUltimate.DLL")]
		private static extern int IBSU_BeginCaptureImage(int handle, IBSU_ImageType imageType, IBSU_ImageResolution imageResolution, uint captureOptions);

		public static int _IBSU_BeginCaptureImage(int handle, IBSU_ImageType imageType, IBSU_ImageResolution imageResolution, uint captureOptions)
		{
			try { return IBSU_BeginCaptureImage(handle, imageType, imageResolution, captureOptions); }
			catch { return -1; }
		}

		[DllImport("IBScanUltimate.DLL")]
		private static extern int IBSU_CancelCaptureImage(int handle);

		public static int _IBSU_CancelCaptureImage(int handle)
		{
			try { return IBSU_CancelCaptureImage(handle); }
			catch { return -1; }
		}

		[DllImport("IBScanUltimate.DLL")]
		private static extern int IBSU_GetErrorString(int errorCode, StringBuilder errorString);

		public static int _IBSU_GetErrorString(int errorCode, StringBuilder errorString)
		{
			try { return IBSU_GetErrorString(errorCode, errorString); }
			catch { return -1; }
		}

		[DllImport("IBScanUltimate.DLL")]
		private static extern int IBSU_EnableTraceLog(bool on);

		public static int _IBSU_EnableTraceLog(bool on)
		{
			try { return IBSU_EnableTraceLog(on); }
			catch { return -1; }
		}

		// ---- LED control (IB C API manual confirmed signatures) ----

		[DllImport("IBScanUltimate.DLL")]
		private static extern int IBSU_SetLEDs(int handle, uint activeLEDs);

		public static int _IBSU_SetLEDs(int handle, uint activeLEDs)
		{
			try { return IBSU_SetLEDs(handle, activeLEDs); }
			catch { return -1; }
		}

		[DllImport("IBScanUltimate.DLL")]
		private static extern int IBSU_SetLEOperationMode(int handle, IBSU_LEOperationMode leOperationMode);

		public static int _IBSU_SetLEOperationMode(int handle, IBSU_LEOperationMode leOperationMode)
		{
			try { return IBSU_SetLEOperationMode(handle, leOperationMode); }
			catch { return -1; }
		}

		// ---- Beeper control (IB C API manual: soundTone 0-2, duration in 25ms units) ----

		[DllImport("IBScanUltimate.DLL")]
		private static extern int IBSU_SetBeeper(int handle, IBSU_BeepPattern beepPattern, uint soundTone, uint duration, uint reserved_1, uint reserved_2);

		public static int _IBSU_SetBeeper(int handle, IBSU_BeepPattern beepPattern, uint soundTone, uint duration)
		{
			try { return IBSU_SetBeeper(handle, beepPattern, soundTone, duration, 0u, 0u); }
			catch { return -1; }
		}

		// ---- NFIQ scoring (IB C API manual confirmed: IBSU_GetNFIQScoreEx) ----
		// Score range: 1 (excellent) - 5 (poor).  Returns IBSU_STATUS_OK (0) on success.

		[DllImport("IBScanUltimate.DLL")]
		private static extern int IBSU_GetNFIQScoreEx(int handle, byte[] imgBuffer, uint width, uint height, int pitch, byte bitsPerPixel, ref int pScore);

		public static int _IBSU_GetNFIQScoreEx(int handle, byte[] imgBuffer, uint width, uint height, int pitch, byte bitsPerPixel, ref int pScore)
		{
			try { return IBSU_GetNFIQScoreEx(handle, imgBuffer, width, height, pitch, bitsPerPixel, ref pScore); }
			catch { return -1; }
		}

		// ---- NFIQ2 scoring (IBScanNFIQ2.DLL) ----
		// Score range: 0-100 (0=poor, 100=excellent). Must call Initialize once before ComputeScore.

		[DllImport("IBScanNFIQ2.DLL", CallingConvention = CallingConvention.Cdecl)]
		private static extern int IBSU_NFIQ2_Initialize();

		[DllImport("IBScanNFIQ2.DLL", CallingConvention = CallingConvention.Cdecl)]
		private static extern bool IBSU_NFIQ2_IsInitialized();

		[DllImport("IBScanNFIQ2.DLL", CallingConvention = CallingConvention.Cdecl)]
		private static extern int IBSU_NFIQ2_ComputeScore(byte[] pImgBuf, uint nWidth, uint nHeight, uint nImgDPI, ref int pScore);

		public static int _IBSU_NFIQ2_Initialize()
		{
			try { return IBSU_NFIQ2_Initialize(); }
			catch (Exception ex) { Console.WriteLine("[NFIQ2] Initialize error: " + ex.Message); return -1; }
		}

		public static bool _IBSU_NFIQ2_IsInitialized()
		{
			try { return IBSU_NFIQ2_IsInitialized(); }
			catch { return false; }
		}

		public static int _IBSU_NFIQ2_ComputeScore(byte[] pImgBuf, uint nWidth, uint nHeight, uint nImgDPI, ref int pScore)
		{
			try { return IBSU_NFIQ2_ComputeScore(pImgBuf, nWidth, nHeight, nImgDPI, ref pScore); }
			catch (Exception ex) { Console.WriteLine("[NFIQ2] ComputeScore error: " + ex.Message); return -1; }
		}
	}
}
