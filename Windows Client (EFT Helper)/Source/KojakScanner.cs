// EFTHelper, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null
// EFTHelper.KojakScanner  (extended: LED guidance + NFIQ2 scoring + rolled capture)
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using IBscanUltimate;

public class KojakScanner : IDisposable
{
	// Standard 10-finger rolled sequence (ANSI/NIST position codes 1-10)
	private static readonly int[] RolledSequence = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

	// ---- Result type for rolled/flat per-finger events ----

	public class FingerResult
	{
		public string Base64;
		public int    FingerPosition;  // 1-10, IBSM standard (1=R Thumb … 10=L Little); 0=composite slap
		public int    Impression;      // 0=LIVE_SCAN_PLAIN, 1=LIVE_SCAN_ROLLED
		public int    Quality;         // 0-100 (100=best), mapped from NFIQ 1-5
		public bool   Rolled;
	}

	// ---- Fields ----

	private int  _devHandle   = -1;
	private bool _isCapturing;

	// Rolled-capture state
	private int  _rolledFingerIndex = -1;  // index into RolledSequence; -1 = not rolling
	private bool _isRolledCapture   = false;

	/// <summary>Set false to suppress all beeper calls.</summary>
	public bool BeeperEnabled { get; set; } = true;

	// Persisted LED mask so callbacks can re-apply after any SDK-internal reset
	private uint _currentLedMask = DLL.IBSU_LED_NONE;
	// Green mask applied on first finger-touch (switches from red waiting → green scanning)
	private uint _activeLedMask  = DLL.IBSU_LED_NONE;

	// Callback delegates – kept as fields to prevent GC collection
	private DLL.IBSU_CallbackPreviewImage        _callbackPreviewImage;
	private DLL.IBSU_CallbackResultImageEx       _callbackResultImageEx;
	private DLL.IBSU_Callback                    _callbackCommunicationBreak;
	private DLL.IBSU_CallbackDeviceCount         _callbackDeviceCount;
	private DLL.IBSU_CallbackTakingAcquisition   _callbackTakingAcquisition;
	private DLL.IBSU_CallbackCompleteAcquisition _callbackCompleteAcquisition;

	// ---- Properties / Events ----

	public bool IsInitialized => _devHandle != -1;

	public event Action<string>              OnPreviewImage;
	public event Action<string, string, int> OnResultImage;
	public event Action<string>              OnStatusMessage;
	public event Action<FingerResult>        OnFingerResult;

	// ---- Constructor ----

	public KojakScanner()
	{
		_callbackPreviewImage        = OnPreviewImageCallback;
		_callbackResultImageEx       = OnResultImageExCallback;
		_callbackCommunicationBreak  = OnCommunicationBreakCallback;
		_callbackDeviceCount         = OnDeviceCountCallback;
		_callbackTakingAcquisition   = OnTakingAcquisitionCallback;
		_callbackCompleteAcquisition = OnCompleteAcquisitionCallback;
		try
		{
			DLL._IBSU_RegisterCallbacks(0, DLL.IBSU_Events.ENUM_IBSU_ESSENTIAL_EVENT_DEVICE_COUNT,
				_callbackDeviceCount, IntPtr.Zero);
		}
		catch { }
	}

	// ---- Public API ----

	public int GetDeviceCount()
	{
		int devices = 0;
		try
		{
			if (DLL._IBSU_GetDeviceCount(ref devices) >= 0)
				return devices;
		}
		catch { }
		return 0;
	}

	public void Initialize()
	{
		Console.WriteLine("Initializing Scanner...");
		try
		{
			DLL._IBSU_EnableTraceLog(on: true);
			DLL.IBSU_SdkVersion ver = default(DLL.IBSU_SdkVersion);
			int rcVer = DLL._IBSU_GetSDKVersion(ref ver);
			Console.WriteLine($"SDK Version: Product={ver.Product}, File={ver.File} (Result={rcVer})");
			int devices = 0;
			int nRc = DLL._IBSU_GetDeviceCount(ref devices);
			Console.WriteLine($"GetDeviceCount Result: {nRc}, Devices Found: {devices}");
			if (nRc < 0)
			{
				StringBuilder errStr = new StringBuilder(128);
				DLL._IBSU_GetErrorString(nRc, errStr);
				Console.WriteLine("GetDeviceCount Error: " + errStr);
				this.OnStatusMessage?.Invoke("Error checking devices: " + errStr);
				return;
			}
			if (devices == 0)
			{
				this.OnStatusMessage?.Invoke("No scanners found.");
				return;
			}
			nRc = DLL._IBSU_OpenDevice(0, ref _devHandle);
			if (nRc >= 0)
			{
				Console.WriteLine("Device Opened. Handle: " + _devHandle);
				this.OnStatusMessage?.Invoke("Device Initialized.");

				// Turn on LED operation mode so SetLEDs calls take effect
				{ int rcM = DLL._IBSU_SetLEOperationMode(_devHandle, DLL.IBSU_LEOperationMode.ENUM_IBSU_LE_OPERATION_ON); Console.WriteLine($"[LED] SetLEOperationMode(ON) init rc={rcM}"); }

				DLL._IBSU_RegisterCallbacks(_devHandle,
					DLL.IBSU_Events.ENUM_IBSU_ESSENTIAL_EVENT_PREVIEW_IMAGE,
					_callbackPreviewImage, IntPtr.Zero);
				DLL._IBSU_RegisterCallbacks(_devHandle,
					DLL.IBSU_Events.ENUM_IBSU_ESSENTIAL_EVENT_RESULT_IMAGE_EX,
					_callbackResultImageEx, IntPtr.Zero);
				DLL._IBSU_RegisterCallbacks(_devHandle,
					DLL.IBSU_Events.ENUM_IBSU_ESSENTIAL_EVENT_COMMUNICATION_BREAK,
					_callbackCommunicationBreak, IntPtr.Zero);
				DLL._IBSU_RegisterCallbacks(_devHandle,
					DLL.IBSU_Events.ENUM_IBSU_ESSENTIAL_EVENT_TAKING_ACQUISITION,
					_callbackTakingAcquisition, IntPtr.Zero);
				DLL._IBSU_RegisterCallbacks(_devHandle,
					DLL.IBSU_Events.ENUM_IBSU_ESSENTIAL_EVENT_COMPLETE_ACQUISITION,
					_callbackCompleteAcquisition, IntPtr.Zero);
			}
			else
			{
				StringBuilder errStr2 = new StringBuilder(128);
				DLL._IBSU_GetErrorString(nRc, errStr2);
				Console.WriteLine($"Failed to open device. Error: {nRc} ({errStr2})");
				this.OnStatusMessage?.Invoke("Failed to open device: " + errStr2);
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine("Exception in Initialize: " + ex);
			this.OnStatusMessage?.Invoke("Error initializing: " + ex.Message);
		}
	}

	public bool StartCapture(string sequenceName)
	{
		Console.WriteLine("StartCapture called for: " + sequenceName);
		if (_devHandle == -1) Initialize();
		if (_devHandle == -1)
		{
			Console.WriteLine("Cannot start capture: Device not initialized.");
			this.OnStatusMessage?.Invoke("Device not initialized.");
			return false;
		}
		if (_isCapturing)
		{
			Console.WriteLine("Capture already in progress.");
			return false;
		}
		_isCapturing     = true;
		_isRolledCapture = false;
		this.OnStatusMessage?.Invoke("Starting capture: " + sequenceName);

		DLL.IBSU_ImageType imageType = DLL.IBSU_ImageType.ENUM_IBSU_FLAT_FOUR_FINGERS;
		uint ledMask = DLL.IBSU_LED_NONE;   // waiting state: progress + red fingers
		_activeLedMask = DLL.IBSU_LED_NONE; // active state:  progress + green fingers (applied on finger touch)
		switch (sequenceName)
		{
			case "L_SLAP":
			case "14":  // Left 4 Fingers (fp_number sent from web UI)
				imageType = DLL.IBSU_ImageType.ENUM_IBSU_FLAT_FOUR_FINGERS;
				ledMask = DLL.IBSU_LED_F_PROGRESS_LEFT_HAND |
				          DLL.IBSU_LED_F_LEFT_INDEX_RED | DLL.IBSU_LED_F_LEFT_MIDDLE_RED |
				          DLL.IBSU_LED_F_LEFT_RING_RED  | DLL.IBSU_LED_F_LEFT_LITTLE_RED;
				_activeLedMask = DLL.IBSU_LED_SCAN_GREEN |
				                 DLL.IBSU_LED_F_PROGRESS_LEFT_HAND |
				                 DLL.IBSU_LED_F_LEFT_INDEX_GREEN | DLL.IBSU_LED_F_LEFT_MIDDLE_GREEN |
				                 DLL.IBSU_LED_F_LEFT_RING_GREEN  | DLL.IBSU_LED_F_LEFT_LITTLE_GREEN;
				break;
			case "R_SLAP":
			case "13":  // Right 4 Fingers
				imageType = DLL.IBSU_ImageType.ENUM_IBSU_FLAT_FOUR_FINGERS;
				ledMask = DLL.IBSU_LED_F_PROGRESS_RIGHT_HAND |
				          DLL.IBSU_LED_F_RIGHT_INDEX_RED | DLL.IBSU_LED_F_RIGHT_MIDDLE_RED |
				          DLL.IBSU_LED_F_RIGHT_RING_RED  | DLL.IBSU_LED_F_RIGHT_LITTLE_RED;
				_activeLedMask = DLL.IBSU_LED_SCAN_GREEN |
				                 DLL.IBSU_LED_F_PROGRESS_RIGHT_HAND |
				                 DLL.IBSU_LED_F_RIGHT_INDEX_GREEN | DLL.IBSU_LED_F_RIGHT_MIDDLE_GREEN |
				                 DLL.IBSU_LED_F_RIGHT_RING_GREEN  | DLL.IBSU_LED_F_RIGHT_LITTLE_GREEN;
				break;
			case "THUMBS":
			case "15":  // Both Thumbs
				imageType = DLL.IBSU_ImageType.ENUM_IBSU_FLAT_TWO_FINGERS;
				ledMask = DLL.IBSU_LED_F_PROGRESS_TWO_THUMB |
				          DLL.IBSU_LED_F_LEFT_THUMB_RED | DLL.IBSU_LED_F_RIGHT_THUMB_RED;
				_activeLedMask = DLL.IBSU_LED_SCAN_GREEN |
				                 DLL.IBSU_LED_F_PROGRESS_TWO_THUMB |
				                 DLL.IBSU_LED_F_LEFT_THUMB_GREEN | DLL.IBSU_LED_F_RIGHT_THUMB_GREEN;
				break;
			case "12":  // Left Thumb Plain
				imageType = DLL.IBSU_ImageType.ENUM_IBSU_FLAT_SINGLE_FINGER;
				ledMask = DLL.IBSU_LED_F_PROGRESS_TWO_THUMB | DLL.IBSU_LED_F_LEFT_THUMB_RED;
				_activeLedMask = DLL.IBSU_LED_SCAN_GREEN | DLL.IBSU_LED_F_PROGRESS_TWO_THUMB | DLL.IBSU_LED_F_LEFT_THUMB_GREEN;
				break;
			case "11":  // Right Thumb Plain
				imageType = DLL.IBSU_ImageType.ENUM_IBSU_FLAT_SINGLE_FINGER;
				ledMask = DLL.IBSU_LED_F_PROGRESS_TWO_THUMB | DLL.IBSU_LED_F_RIGHT_THUMB_RED;
				_activeLedMask = DLL.IBSU_LED_SCAN_GREEN | DLL.IBSU_LED_F_PROGRESS_TWO_THUMB | DLL.IBSU_LED_F_RIGHT_THUMB_GREEN;
				break;
			default:
				// Single rolled finger by position number (1-10)
				if (int.TryParse(sequenceName, out int fingerPos) && fingerPos >= 1 && fingerPos <= 10)
				{
					imageType = DLL.IBSU_ImageType.ENUM_IBSU_ROLL_SINGLE_FINGER;
					uint handProgress = (fingerPos == 1 || fingerPos == 6)
						? DLL.IBSU_LED_F_PROGRESS_TWO_THUMB
						: fingerPos <= 5
							? DLL.IBSU_LED_F_PROGRESS_RIGHT_HAND
							: DLL.IBSU_LED_F_PROGRESS_LEFT_HAND;
					ledMask        = DLL.IBSU_LED_F_PROGRESS_ROLL | handProgress | GetFingerLedRed(fingerPos);
					_activeLedMask = DLL.IBSU_LED_F_PROGRESS_ROLL | handProgress | GetFingerLedGreen(fingerPos);
					this.OnStatusMessage?.Invoke($"Roll {GetFingerName(fingerPos)} — nail to nail");
				}
				break;
		}

		int nRc = DLL._IBSU_BeginCaptureImage(_devHandle, imageType,
			DLL.IBSU_ImageResolution.ENUM_IBSU_IMAGE_RESOLUTION_500, 7u);
		Console.WriteLine("BeginCaptureImage Result: " + nRc);
		if (nRc < 0)
		{
			this.OnStatusMessage?.Invoke("Failed to start capture: " + nRc);
			_isCapturing = false;
			SetLeds(DLL.IBSU_LED_NONE);
			return false;
		}
		if (ledMask != DLL.IBSU_LED_NONE)
		{
			// Re-assert user LED control — BeginCaptureImage may reset mode to AUTO
			{ int rcM = DLL._IBSU_SetLEOperationMode(_devHandle, DLL.IBSU_LEOperationMode.ENUM_IBSU_LE_OPERATION_ON); Console.WriteLine($"[LED] SetLEOperationMode(ON) StartCapture rc={rcM}"); }
			SetLeds(ledMask);
			// For flat captures the SDK continuously resets guidance LEDs during the preview loop.
			// Re-apply every 200ms to keep them visible (~1ms off per cycle = invisible).
			// For rolled, the SDK does NOT reset LEDs so one SetLeds call is enough.
			bool isFlat = sequenceName == "L_SLAP" || sequenceName == "R_SLAP" || sequenceName == "THUMBS"
			           || sequenceName == "11" || sequenceName == "12" || sequenceName == "13"
			           || sequenceName == "14" || sequenceName == "15";
			if (isFlat)
			{
				ThreadPool.QueueUserWorkItem(_ =>
				{
					while (_isCapturing && _devHandle != -1)
					{
						Thread.Sleep(200);
						if (_isCapturing && _devHandle != -1)
					{
						DLL._IBSU_SetLEOperationMode(_devHandle, DLL.IBSU_LEOperationMode.ENUM_IBSU_LE_OPERATION_ON);
						DLL._IBSU_SetLEDs(_devHandle, _currentLedMask);
					}
					}
				});
			}
		}
		return true;
	}

	// ---- Rolled capture sequence ----

	public bool StartRolledSequence()
	{
		if (_devHandle == -1) Initialize();
		if (_devHandle == -1)
		{
			this.OnStatusMessage?.Invoke("Device not initialized.");
			return false;
		}
		if (_isCapturing)
		{
			Console.WriteLine("Capture already in progress.");
			return false;
		}
		_isRolledCapture    = true;
		_rolledFingerIndex  = 0;
		_isCapturing        = true;
		this.OnStatusMessage?.Invoke("Starting rolled capture sequence (10 fingers)...");
		AdvanceRoll();
		return true;
	}

	private void AdvanceRoll()
	{
		if (_rolledFingerIndex < 0 || _rolledFingerIndex >= RolledSequence.Length)
		{
			// All fingers done
			_isRolledCapture   = false;
			_rolledFingerIndex = -1;
			_isCapturing       = false;
			SetLeds(DLL.IBSU_LED_NONE);
			this.OnStatusMessage?.Invoke("Rolled capture sequence complete.");
			return;
		}

		int    fingerPos  = RolledSequence[_rolledFingerIndex];
		string fingerName = GetFingerName(fingerPos);
		this.OnStatusMessage?.Invoke($"Roll finger {_rolledFingerIndex + 1}/10: {fingerName}");

		// Roll-progress indicator: red while waiting, green when finger touches (OnTakingAcquisition switches)
		uint handProg = (fingerPos == 1 || fingerPos == 6)
			? DLL.IBSU_LED_F_PROGRESS_TWO_THUMB
			: fingerPos <= 5
				? DLL.IBSU_LED_F_PROGRESS_RIGHT_HAND
				: DLL.IBSU_LED_F_PROGRESS_LEFT_HAND;
		_activeLedMask = DLL.IBSU_LED_F_PROGRESS_ROLL | handProg | GetFingerLedGreen(fingerPos);
		SetLeds(DLL.IBSU_LED_F_PROGRESS_ROLL | handProg | GetFingerLedRed(fingerPos));

		int nRc = DLL._IBSU_BeginCaptureImage(_devHandle,
			DLL.IBSU_ImageType.ENUM_IBSU_ROLL_SINGLE_FINGER,
			DLL.IBSU_ImageResolution.ENUM_IBSU_IMAGE_RESOLUTION_500,
			7u);  // auto-contrast | auto-capture | ignore-finger-count

		Console.WriteLine($"[Roll] BeginCapture finger {fingerPos} ({fingerName}): {nRc}");
		if (nRc < 0)
		{
			this.OnStatusMessage?.Invoke($"Failed to start roll for {fingerName}: {nRc}");
			_isRolledCapture   = false;
			_rolledFingerIndex = -1;
			_isCapturing       = false;
			SetLeds(DLL.IBSU_LED_NONE);
		}
	}

	public void CancelCapture()
	{
		if (_devHandle != -1)
		{
			Console.WriteLine("Cancelling Capture...");
			DLL._IBSU_CancelCaptureImage(_devHandle);
			_isCapturing       = false;
			_isRolledCapture   = false;
			_rolledFingerIndex = -1;
			_currentLedMask    = DLL.IBSU_LED_NONE;
			SetLeds(DLL.IBSU_LED_NONE);
			this.OnStatusMessage?.Invoke("Capture Cancelled");
		}
	}

	public void Dispose()
	{
		if (_devHandle != -1)
		{
			Console.WriteLine("Closing Device...");
			SetLeds(DLL.IBSU_LED_NONE);
			DLL._IBSU_CloseDevice(_devHandle);
			_devHandle = -1;
		}
	}

	// ---- SDK Callbacks ----

	private void OnTakingAcquisitionCallback(int deviceHandle, IntPtr pContext, DLL.IBSU_ImageType imageType)
	{
		// Finger has touched the platen — switch from red-waiting to green-scanning mask.
		if (_activeLedMask != DLL.IBSU_LED_NONE)
			SetLeds(_activeLedMask);
		else if (_currentLedMask != DLL.IBSU_LED_NONE && _devHandle != -1)
			DLL._IBSU_SetLEDs(_devHandle, _currentLedMask);

		if (_isRolledCapture && _rolledFingerIndex >= 0 && _rolledFingerIndex < RolledSequence.Length)
		{
			string fingerName = GetFingerName(RolledSequence[_rolledFingerIndex]);
			this.OnStatusMessage?.Invoke($"Rolling {fingerName} — roll nail to nail now");
		}
	}

	private void OnCompleteAcquisitionCallback(int deviceHandle, IntPtr pContext, DLL.IBSU_ImageType imageType)
	{
		if (_isRolledCapture)
			this.OnStatusMessage?.Invoke("Roll complete — processing image...");
	}

	private void OnPreviewImageCallback(int deviceHandle, IntPtr pContext, IntPtr pImage)
	{
		// Preview fires continuously — do NOT switch LEDs here (would go green before fingers touch).
		try
		{
			if (!(pImage != IntPtr.Zero)) return;
			DLL.IBSU_ImageData image = (DLL.IBSU_ImageData)Marshal.PtrToStructure(pImage, typeof(DLL.IBSU_ImageData));
			if (image.Buffer != IntPtr.Zero && image.Width != 0 && image.Width < 10000
				&& image.Height != 0 && image.Height < 10000)
			{
				using (Bitmap bmp = CreateBitmapFromIBSU(image))
				{
					if (bmp != null)
					{
						bmp.RotateFlip(System.Drawing.RotateFlipType.Rotate180FlipX);
						string base64 = ImageToBase64(bmp, ImageFormat.Png);
						this.OnPreviewImage?.Invoke(base64);
					}
				}
				return;
			}
			Console.WriteLine($"[Preview] Bad Image Data: W={image.Width} H={image.Height} Buffer={image.Buffer}");
		}
		catch (Exception ex)
		{
			Console.WriteLine("Preview Error: " + ex.Message);
		}
	}

	private void OnResultImageExCallback(int deviceHandle, IntPtr pContext, int imageStatus,
		IntPtr pImage, DLL.IBSU_ImageType imageType, int detectedFingerCount,
		int segmentImageArrayCount, IntPtr pSegmentImageArray, IntPtr pSegmentPositionArray)
	{
		Console.WriteLine("Result Callback. Status: " + imageStatus);

		// Snapshot rolled state before any async side-effects
		bool wasRolled    = _isRolledCapture;
		int  rolledIndex  = _rolledFingerIndex;

		if (imageStatus >= 0)
		{
			try
			{
				if (pImage != IntPtr.Zero)
				{
					DLL.IBSU_ImageData image = (DLL.IBSU_ImageData)Marshal.PtrToStructure(pImage, typeof(DLL.IBSU_ImageData));
					using Bitmap bmp = CreateBitmapFromIBSU(image);
					if (bmp != null)
					{
						bmp.RotateFlip(System.Drawing.RotateFlipType.Rotate180FlipX);
						string base64  = ImageToBase64(bmp, ImageFormat.Png);
						int    quality = ComputeNfiqQuality(image);

						if (wasRolled && rolledIndex >= 0 && rolledIndex < RolledSequence.Length)
						{
							int    fingerPos  = RolledSequence[rolledIndex];
							string fingerName = GetFingerName(fingerPos);

							// Solid green = finger accepted
							uint acceptProg = (fingerPos == 1 || fingerPos == 6)
								? DLL.IBSU_LED_F_PROGRESS_TWO_THUMB
								: fingerPos <= 5
									? DLL.IBSU_LED_F_PROGRESS_RIGHT_HAND
									: DLL.IBSU_LED_F_PROGRESS_LEFT_HAND;
							SetLeds(DLL.IBSU_LED_F_PROGRESS_ROLL | acceptProg | GetFingerLedGreen(fingerPos));

							this.OnFingerResult?.Invoke(new FingerResult
							{
								Base64         = base64,
								FingerPosition = fingerPos,
								Impression     = 1,   // IBSM_IMPRESSION_TYPE_LIVE_SCAN_ROLLED
								Quality        = quality,
								Rolled         = true
							});
							this.OnStatusMessage?.Invoke($"Captured: {fingerName} (quality {quality})");

							// Advance to next finger after a short gap
							_rolledFingerIndex++;
							ThreadPool.QueueUserWorkItem(_ =>
							{
								Thread.Sleep(400);
								AdvanceRoll();
							});
							// _isCapturing stays true — sequence continues
						}
						else
						{
							// Flat slap or single rolled finger — pause for user review
							SetLeds(DLL.IBSU_LED_NONE);
							// Success beep: tone=1 (mid), duration=8 × 25ms = 200ms
							if (BeeperEnabled) DLL._IBSU_SetBeeper(_devHandle, DLL.IBSU_BeepPattern.ENUM_IBSU_BEEP_PATTERN_GENERIC, 1u, 8u);
							this.OnResultImage?.Invoke(base64, "Result", quality);
							this.OnStatusMessage?.Invoke("Capture Success");
							_isCapturing = false;
						}
					}
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine("Result Error: " + ex.Message);
				this.OnStatusMessage?.Invoke("Capture processing failed: " + ex.Message);
				_isCapturing       = false;
				_isRolledCapture   = false;
				_rolledFingerIndex = -1;
				SetLeds(DLL.IBSU_LED_NONE);
			}
		}
		else
		{
			this.OnStatusMessage?.Invoke("Capture Failed: " + imageStatus);
			// Error beep: tone=0 (low), duration=16 × 25ms = 400ms
			if (BeeperEnabled) DLL._IBSU_SetBeeper(_devHandle, DLL.IBSU_BeepPattern.ENUM_IBSU_BEEP_PATTERN_GENERIC, 0u, 16u);
			_isCapturing       = false;
			_isRolledCapture   = false;
			_rolledFingerIndex = -1;
			SetLeds(DLL.IBSU_LED_NONE);
		}
	}

	private void OnCommunicationBreakCallback(int deviceIndex, IntPtr pContext)
	{
		Console.WriteLine("Communication Break!");
		this.OnStatusMessage?.Invoke("Device Communication Break");
		_devHandle         = -1;
		_isCapturing       = false;
		_isRolledCapture   = false;
		_rolledFingerIndex = -1;
	}

	private void OnDeviceCountCallback(int detectedDevices, IntPtr pContext)
	{
		Console.WriteLine("Device Count Changed: " + detectedDevices);
		this.OnStatusMessage?.Invoke("Scanner(s) detected: " + detectedDevices);
	}

	// ---- LED helpers ----

	private void SetLeds(uint ledMask)
	{
		_currentLedMask = ledMask;
		if (_devHandle != -1)
		{
			int rc = DLL._IBSU_SetLEDs(_devHandle, ledMask);
			Console.WriteLine($"[LED] SetLEDs(0x{ledMask:X}) rc={rc}");
		}
		else Console.WriteLine($"[LED] SetLEDs skipped — no device");
	}

	// Public wrapper used by the LED Test Panel (LedTestForm) for manual bit testing.
	public void TestSetLeds(uint mask) => SetLeds(mask);

	private static uint GetFingerLedRed(int fingerPosition)
	{
		switch (fingerPosition)
		{
			case 1:  return DLL.IBSU_LED_F_RIGHT_THUMB_RED;
			case 2:  return DLL.IBSU_LED_F_RIGHT_INDEX_RED;
			case 3:  return DLL.IBSU_LED_F_RIGHT_MIDDLE_RED;
			case 4:  return DLL.IBSU_LED_F_RIGHT_RING_RED;
			case 5:  return DLL.IBSU_LED_F_RIGHT_LITTLE_RED;
			case 6:  return DLL.IBSU_LED_F_LEFT_THUMB_RED;
			case 7:  return DLL.IBSU_LED_F_LEFT_INDEX_RED;
			case 8:  return DLL.IBSU_LED_F_LEFT_MIDDLE_RED;
			case 9:  return DLL.IBSU_LED_F_LEFT_RING_RED;
			case 10: return DLL.IBSU_LED_F_LEFT_LITTLE_RED;
			default: return DLL.IBSU_LED_NONE;
		}
	}

	private static uint GetFingerLedGreen(int fingerPosition)
	{
		switch (fingerPosition)
		{
			case 1:  return DLL.IBSU_LED_F_RIGHT_THUMB_GREEN;
			case 2:  return DLL.IBSU_LED_F_RIGHT_INDEX_GREEN;
			case 3:  return DLL.IBSU_LED_F_RIGHT_MIDDLE_GREEN;
			case 4:  return DLL.IBSU_LED_F_RIGHT_RING_GREEN;
			case 5:  return DLL.IBSU_LED_F_RIGHT_LITTLE_GREEN;
			case 6:  return DLL.IBSU_LED_F_LEFT_THUMB_GREEN;
			case 7:  return DLL.IBSU_LED_F_LEFT_INDEX_GREEN;
			case 8:  return DLL.IBSU_LED_F_LEFT_MIDDLE_GREEN;
			case 9:  return DLL.IBSU_LED_F_LEFT_RING_GREEN;
			case 10: return DLL.IBSU_LED_F_LEFT_LITTLE_GREEN;
			default: return DLL.IBSU_LED_NONE;
		}
	}

	private static string GetFingerName(int fingerPosition)
	{
		switch (fingerPosition)
		{
			case 1:  return "Right Thumb";
			case 2:  return "Right Index";
			case 3:  return "Right Middle";
			case 4:  return "Right Ring";
			case 5:  return "Right Little";
			case 6:  return "Left Thumb";
			case 7:  return "Left Index";
			case 8:  return "Left Middle";
			case 9:  return "Left Ring";
			case 10: return "Left Little";
			default: return $"Finger {fingerPosition}";
		}
	}

	// ---- NFIQ quality scoring ----

	private static bool _nfiq2Initialized = false;

	private static void EnsureNfiq2Initialized()
	{
		if (_nfiq2Initialized) return;
		int rc = DLL._IBSU_NFIQ2_Initialize();
		_nfiq2Initialized = (rc >= 0) || DLL._IBSU_NFIQ2_IsInitialized();
		Console.WriteLine($"[NFIQ2] Initialize rc={rc} initialized={_nfiq2Initialized}");
	}

	// NFIQ2 score 0-100 (100=best). Falls back to NFIQ1 mapped 0-100 if NFIQ2 fails.
	private int ComputeNfiqQuality(DLL.IBSU_ImageData image)
	{
		try
		{
			if (image.Buffer == IntPtr.Zero || image.Width == 0 || image.Height == 0)
				return 50;

			int bufLen = Math.Abs(image.Pitch) * (int)image.Height;
			byte[] buf = new byte[bufLen];
			Marshal.Copy(image.Buffer, buf, 0, bufLen);

			// Try NFIQ2 first (true 0-100 score)
			EnsureNfiq2Initialized();
			if (_nfiq2Initialized)
			{
				int nfiq2Score = 0;
				uint dpi = (image.ResolutionX > 0) ? (uint)Math.Round(image.ResolutionX) : 500u;
				int rc2 = DLL._IBSU_NFIQ2_ComputeScore(buf, image.Width, image.Height, dpi, ref nfiq2Score);
				Console.WriteLine($"[NFIQ2] rc={rc2} score={nfiq2Score} dpi={dpi} w={image.Width} h={image.Height}");
				if (rc2 >= 0 && nfiq2Score >= 0 && nfiq2Score <= 100)
					return nfiq2Score;
				Console.WriteLine("[NFIQ2] Failed, falling back to NFIQ1");
			}

			// Fallback: NFIQ1 (1-5) mapped to 0-100
			int score1 = 0;
			int rc1 = DLL._IBSU_GetNFIQScoreEx(_devHandle, buf,
				image.Width, image.Height, image.Pitch, image.BitsPerPixel, ref score1);
			Console.WriteLine($"[NFIQ1] rc={rc1} score={score1}");
			if (rc1 >= 0 && score1 >= 1 && score1 <= 5)
				return (5 - score1) * 25;  // NFIQ 1→100, 2→75, 3→50, 4→25, 5→0
		}
		catch (Exception ex)
		{
			Console.WriteLine("[NFIQ] Error: " + ex.Message);
		}
		Console.WriteLine("[NFIQ] Returning fallback 50");
		return 50;  // neutral fallback
	}

	// ---- Image helpers ----

	private Bitmap CreateBitmapFromIBSU(DLL.IBSU_ImageData image)
	{
		try
		{
			int width  = (int)image.Width;
			int height = (int)image.Height;
			int stride = Math.Abs(image.Pitch);
			if (width <= 0 || width > 10000 || height <= 0 || height > 10000 || image.Buffer == IntPtr.Zero)
			{
				Console.WriteLine($"Bitmap Sanity Check Failed: W={width} H={height} Buf={image.Buffer}");
				return null;
			}
			PixelFormat fmt = PixelFormat.Format8bppIndexed;
			Bitmap bmp = new Bitmap(width, height, fmt);
			BitmapData bmpData = bmp.LockBits(new Rectangle(0, 0, width, height),
				ImageLockMode.WriteOnly, fmt);
			// Set grayscale palette for 8bpp indexed
			ColorPalette palette = bmp.Palette;
			for (int i = 0; i < 256; i++)
				palette.Entries[i] = Color.FromArgb(255, i, i, i);
			bmp.Palette = palette;

			byte[] row = new byte[width];
			IntPtr srcPtr = image.Buffer;
			for (int y = 0; y < height; y++)
			{
				Marshal.Copy(srcPtr, row, 0, width);
				IntPtr dstPtr = bmpData.Scan0 + y * bmpData.Stride;
				Marshal.Copy(row, 0, dstPtr, width);
				srcPtr += stride;
			}
			bmp.UnlockBits(bmpData);
			return bmp;
		}
		catch (Exception ex)
		{
			Console.WriteLine("CreateBitmapFromIBSU Error: " + ex.Message);
			return null;
		}
	}

	private static string ImageToBase64(Bitmap bmp, ImageFormat format)
	{
		using (var ms = new MemoryStream())
		{
			bmp.Save(ms, format);
			return Convert.ToBase64String(ms.ToArray());
		}
	}
}
